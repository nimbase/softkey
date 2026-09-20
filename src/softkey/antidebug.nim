# Runtime anti-debug checks (tamper resistance, not a trust boundary).
#
# The library never terminates the process. Call enforceNoDebugger()
# before license validation; it raises DebuggerDetected and the host
# application decides what to do (wipe secrets, quit, limited mode).
#
# Compile-time dev bypass:
#   clue build app.nim -- -d:softkeyNoAntidebug
# With -d:softkeyNoAntidebug, enforceNoDebugger() is a no-op so devs can
# debug with softkey enabled. checkRuntimeEnvironment() still runs the
# real checks so diagnostics stay truthful.
#
# Test overrides (never set in production):
#   SOFTKEY_FORCE_DEBUG=1  pretend a debugger is attached
#   SOFTKEY_FORCE_CLEAN=1  pretend the environment is clean
#
# A local owner can always NOP these checks. They deter casual
# tampering only; real enforcement belongs server-side with short
# token lifetimes.

import std/monotimes
import std/os
import std/strutils

import ./license_types

export license_types

type
  DebuggerDetected* = object of CatchableError
    ## Raised by enforceNoDebugger(). Carries the triggering status.
    status*: SecurityStatus

const
  ForceDebugEnv = "SOFTKEY_FORCE_DEBUG"
  ForceCleanEnv = "SOFTKEY_FORCE_CLEAN"

when defined(linux):
  proc linuxTracerPid(): bool =
    ## True when /proc/self/status reports a non-zero TracerPid.
    var f: File
    if not open(f, "/proc/self/status", fmRead):
      return false
    defer: close(f)
    for line in f.lines:
      if line.startsWith("TracerPid:"):
        let parts = line.splitWhitespace()
        if parts.len >= 2:
          try:
            return parseInt(parts[1].strip()) != 0
          except ValueError:
            return false
    false

  proc linuxPreloadPresent(): bool =
    getEnv("LD_PRELOAD", "").len > 0

when defined(macosx):
  import std/posix

  const
    MacMibKern = 1.cint
    MacMibKernProc = 14.cint
    MacMibKernProcPid = 1.cint
    MacPTraced = 0x00000800'i32
    MacKinfoSize = 648
    MacPFlagOff = 64

  proc c_sysctl(mib: ptr cint, miblen: cuint, oldp: pointer,
      oldlenp: ptr csize_t, newp: pointer,
      newlen: csize_t): cint {.importc: "sysctl",
      header: "<sys/sysctl.h>".}

  proc macosTraced(): bool =
    ## True when the sysctl KERN_PROC_PID p_flag has P_TRACED.
    ## Reads p_flag at its byte offset inside struct kinfo_proc so the
    ## full 648-byte struct never needs a Nim mirror. Best effort:
    ## any failure returns false (no assertion).
    var mib: array[4, cint] = [MacMibKern, MacMibKernProc,
      MacMibKernProcPid, cint(getpid())]
    var size: csize_t = MacKinfoSize.csize_t
    var buf: array[MacKinfoSize, byte]
    if c_sysctl(addr mib[0], 4, addr buf[0], addr size, nil, 0) != 0:
      return false
    var flag: cint
    copyMem(addr flag, unsafeAddr buf[MacPFlagOff], sizeof(flag))
    (flag and MacPTraced) != 0

when defined(windows):
  proc IsDebuggerPresent(): cint {.stdcall, dynlib: "kernel32",
    importc.}
  proc GetCurrentProcess(): pointer {.stdcall, dynlib: "kernel32",
    importc.}
  proc CheckRemoteDebuggerPresent(hProcess: pointer,
      present: ptr cint): cint {.stdcall, dynlib: "kernel32", importc.}

  proc windowsDebugged(): bool =
    if IsDebuggerPresent() != 0:
      return true
    var present: cint = 0
    if CheckRemoteDebuggerPresent(GetCurrentProcess(), addr present) != 0:
      return present != 0
    false

proc timingAnomaly(): bool =
  ## True when a trivial loop takes absurdly long (single-stepping).
  ## Threshold is deliberately generous to avoid false positives.
  let t0 = getMonoTime().ticks
  var acc = 0
  for i in 0 ..< 200_000:
    acc += i and 7
  let dtMs = (getMonoTime().ticks - t0) div 1_000_000
  discard acc
  dtMs > 1500

proc platformCheck(): SecurityStatus =
  ## Single native verdict, or unsupportedEnvironment where unimplemented.
  when defined(linux):
    if linuxTracerPid() or linuxPreloadPresent():
      return debuggerDetected
    securityOk
  elif defined(macosx):
    if macosTraced():
      return debuggerDetected
    securityOk
  elif defined(windows):
    try:
      if windowsDebugged():
        return debuggerDetected
    except CatchableError:
      return unsupportedEnvironment
    securityOk
  else:
    unsupportedEnvironment

proc checkRuntimeEnvironment*(): SecurityStatus =
  ## Non-raising environment probe for diagnostics and tests.
  ## Test overrides take precedence over native checks.
  if getEnv(ForceDebugEnv, "") == "1":
    return debuggerDetected
  if getEnv(ForceCleanEnv, "") == "1":
    return securityOk
  let native = platformCheck()
  if native == debuggerDetected:
    return debuggerDetected
  try:
    if timingAnomaly():
      return debuggerDetected
  except CatchableError:
    discard
  native

proc enforceNoDebugger*(policy: AntiDebugPolicy) =
  ## Raise DebuggerDetected when a tracer is found and policy.enabled.
  ## No-op when -d:softkeyNoAntidebug is defined (dev bypass) or when
  ## the policy is disabled. Unsupported environments raise only when
  ## allowUnsupported is false.
  when defined(softkeyNoAntidebug):
    return
  if not policy.enabled:
    return
  case checkRuntimeEnvironment()
  of debuggerDetected:
    var err = newException(DebuggerDetected, "debugger detected")
    err.status = debuggerDetected
    raise err
  of unsupportedEnvironment:
    if not policy.allowUnsupported:
      var err = newException(DebuggerDetected,
        "unsupported environment for anti-debug check")
      err.status = unsupportedEnvironment
      raise err
  of securityOk:
    discard
