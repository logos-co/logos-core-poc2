# src/shell.nim
# Logos shell module — native C ABI per LOGOS-MODULE-INTERFACE §2.4/§2.6.
#
# Exports the identity/lifecycle symbols, the provider symbols
# (_call_surface, _free, _dispatch), and the schema-derived per-method
# function logos_shell_call_shell_exec.

import std/osproc
import results
import logos_core/[abi_types, cbor_profile, call_surface]

# ============================================================================
# Schema (no _version; methods as request/response pairs)
# ============================================================================

const shellSchema* = """
; -- metadata --
_module = "shell"

; -- methods --
shell.exec_request = {
    command: tstr,
    args: tstr,
}

shell.exec_response = {
    output: tstr,
}
"""

const moduleName* = "shell"

# ============================================================================
# Per-instance context (module-owned opaque state)
# ============================================================================

## The shell module is stateless; the context is a raw opaque marker
## allocated with alloc0 and released with dealloc0 in _destroy.
type ShellContext = pointer

# ============================================================================
# Core functionality
# ============================================================================

proc execImplementation(command: string): string =
  try:
    execProcess(command)
  except:
    "Error: Failed to execute command"

proc runExec(command, args: string): string =
  ## The command and args are combined into a single shell command line.
  let cmd = command & (if args.len > 0: " " & args else: "")
  execImplementation(cmd)

proc encodeExecResponse(output: string): seq[byte] =
  encodeCbor(cborMap((cborValue("output"), cborValue(output))))

proc decodeExecRequest(payload: seq[byte]): Result[(string, string), string] =
  ## strict deterministic-CBOR closed map {command: tstr, args: tstr}
  var v: CborValue
  try:
    v = decodeCbor(payload)
  except CborError as e:
    return err(e.msg)
  if not validateDeterministic(payload):
    return err("request is not deterministic CBOR")
  if v.kind != ckMap:
    return err("request is not a map")
  var command, args: string
  var haveCmd, haveArgs = false
  for (k, val) in v.entries:
    case k.s
    of "command":
      if val.kind != ckText:
        return err("command must be a text string")
      command = val.s
      haveCmd = true
    of "args":
      if val.kind != ckText:
        return err("args must be a text string")
      args = val.s
      haveArgs = true
    else:
      return err("unknown request field " & k.s)
  if not haveCmd:
    return err("missing command field")
  if not haveArgs:
    return err("missing args field")
  ok((command, args))

# ============================================================================
# Identity and lifecycle symbols (INTERFACE §2.6)
# ============================================================================

proc logos_shell_name(): cstring {.exportc, dynlib.} =
  moduleName.cstring

proc logos_shell_init(
    input: ptr LogosModuleInitInput, outContext: ptr LogosModuleContext
): LogosResult {.exportc, dynlib.} =
  # versioned-struct consumer rules (INTERFACE §5.2)
  if input.abiVersion != LOGOS_MODULE_INIT_ABI_VERSION:
    return LogosResult(
      code: LOGOS_ERR_VERSION_MISMATCH, message: "unsupported ABI version".cstring
    )
  if input.structSize < sizeof(LogosModuleInitInput).csize_t:
    return LogosResult(
      code: LOGOS_ERR_VERSION_MISMATCH,
      message: "initialization struct too small".cstring,
    )
  let ctx = cast[ShellContext](alloc0(16))
  outContext[] = ctx
  LogosResult(code: LOGOS_OK, message: nil)

proc logos_shell_destroy(module: LogosModuleContext) {.exportc, dynlib.} =
  if module != nil:
    dealloc(module)

# ============================================================================
# Provider symbols (INTERFACE §2.6)
# ============================================================================

## The call-surface descriptor is built once and returned as the same static
## bytes on every call (INTERFACE §2.6 "MUST return the same bytes on every");
## the caller MUST NOT free it (§2.7), so the buffer lives for the process.
var cachedShellSurface: ptr uint8 = nil
var cachedShellSurfaceLen: csize_t = 0

proc logos_shell_call_surface(outLen: ptr csize_t): ptr uint8 {.exportc, dynlib.} =
  if cachedShellSurface == nil:
    let desc = buildCallSurface(shellSchema, @[], @[])
    cachedShellSurface = cast[ptr uint8](alloc0(desc.len))
    copyMem(cachedShellSurface, addr desc[0], desc.len)
    cachedShellSurfaceLen = desc.len.csize_t
  outLen[] = cachedShellSurfaceLen
  cachedShellSurface

proc logos_shell_free(module: LogosModuleContext, p: pointer) {.exportc, dynlib.} =
  discard module
  if p != nil:
    deallocShared(p)

proc logos_shell_dispatch(
    module: LogosModuleContext,
    methodName: cstring,
    paramsCbor: ptr uint8,
    paramsLen: csize_t,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let meth = $methodName
  if meth != "exec":
    outResponseCbor[] = nil
    outResponseLen[] = 0
    return
      LogosResult(code: LOGOS_ERR_METHOD_NOT_FOUND, message: "unknown method".cstring)
  var payload = newSeq[byte](paramsLen)
  if paramsLen > 0 and paramsCbor != nil:
    copyMem(addr payload[0], paramsCbor, paramsLen)
  let req = decodeExecRequest(payload)
  if req.isErr:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    return LogosResult(code: LOGOS_ERR_INVALID_PARAMS, message: req.error.cstring)
  let (command, args) = req.get
  let output = runExec(command, args)
  let resp = encodeExecResponse(output)
  let buf = cast[ptr uint8](allocShared(resp.len))
  copyMem(buf, addr resp[0], resp.len)
  outResponseCbor[] = buf
  outResponseLen[] = resp.len.csize_t
  LogosResult(code: LOGOS_OK, message: nil)

# ============================================================================
# Schema-derived per-method function (INTERFACE §2.4)
# ============================================================================

proc logos_shell_call_shell_exec(
    module: LogosModuleContext,
    inCommand: cstring,
    inArgs: cstring,
    outOutput: ptr cstring,
): LogosResult {.exportc, dynlib.} =
  discard module
  let command = $inCommand
  let args =
    if inArgs != nil:
      $inArgs
    else:
      ""
  let output = runExec(command, args)
  # provider-allocated NUL-terminated string, freed by the caller with
  # logos_shell_free(module, ptr) (INTERFACE §2.7)
  let buf = cast[ptr cstring](allocShared(output.len + 1))
  copyMem(buf, output.cstring, output.len + 1)
  outOutput[] = cast[cstring](buf)
  LogosResult(code: LOGOS_OK, message: nil)
