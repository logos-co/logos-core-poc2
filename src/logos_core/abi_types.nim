# src/logos_core/abi_types.nim
# C ABI function pointer types for Logos module interface.
# Per LOGOS-MODULE-INTERFACE §2.6

{.pragma: capi, cdecl, raises: [], gcsafe.}

# ============================================================================
# Error codes (reexport source)
# ============================================================================

## Error codes for the Logos protocol - matches logos_common.cddl
const
  LOGOS_OK* = 0
  LOGOS_ERR_METHOD_NOT_FOUND* = 1
  LOGOS_ERR_INVALID_PARAMS* = 2
  LOGOS_ERR_MODULE* = 3
  LOGOS_ERR_NOT_AUTHORISED* = 4
  LOGOS_ERR_TRANSPORT* = 5
  LOGOS_ERR_TIMEOUT* = 6
  LOGOS_ERR_VERSION_MISMATCH* = 7
  LOGOS_ERR_NOT_READY* = 8
  LOGOS_ERR_CANCELLED* = 9

# ============================================================================
# C ABI function pointer types
# Per LOGOS-MODULE-INTERFACE §2.6
# ============================================================================

type
  ## Bootstrap symbol — discovers the module name
  LogosNameFnAbi* = proc(): cstring {.capi.}

  ## Module metadata getter
  LogosSchemaFnAbi* = proc(): cstring {.capi.}

  ## Module metadata getter
  LogosVersionFnAbi* = proc(): cstring {.capi.}

  ## Lifecycle _init (called once after loading the shared library)
  ## NOTE: not to be confused with a schema method named "init".
  LogosInitFnAbi* = proc(): cint {.capi.}

  ## Lifecycle destroy (called before unloading the shared library)
  LogosDestroyFnAbi* = proc() {.capi.}

  ## Mandatory: generic CBOR dispatch entrypoint
  ## Per LOGOS-MODULE-INTERFACE §2.4/2.6
  ## - methodName: bare schema method name (e.g. "exists")
  ## - paramsCbor: deterministic CBOR request map (raw bytes)
  ## - paramsLen: length of paramsCbor
  ## - outResponseCbor: callee-allocated response CBOR (freed with module's freeFn)
  ## - outResponseLen: length of outResponseCbor
  ## Returns: 0 on success, non-zero Logos error code on failure
  LogosDispatchFnAbi* = proc(
    ctx: pointer,
    meth: cstring,
    requestPayload: ptr uint8,
    requestLen: csize_t,
    responsePayload: ptr ptr uint8,
    responseLen: ptr csize_t,
  ): cint {.capi.}

  ## Mandatory: memory deallocator for response buffers
  ## Per LOGOS-MODULE-INTERFACE §2.7
  LogosFreeFnAbi* = proc(p: pointer) {.capi.}

  ## Raw publish callback (event data as pointer + length)
  ## Per LOGOS-MODULE-RUNTIME §7.4
  LogosPublishFnAbi* = proc(eventData: pointer, eventLen: csize_t) {.capi.}

  ## Setter for the publish callback
  LogosSetPublishFnAbi* = proc(
    fn: proc(eventData: pointer, eventLen: csize_t) {.capi.}, userData: pointer
  ) {.capi.}

  ## Raw call-module callback (raw pointer/len for inter-module calls)
  ## Per LOGOS-MODULE-RUNTIME §7.5
  LogosCallModuleFnAbi* = proc(
    targetModule: cstring,
    requestCbor: pointer,
    requestLen: csize_t,
    responseCbor: ptr ptr uint8,
    responseLen: ptr csize_t,
  ): cint {.capi.}

  ## Response deallocator for call-module
  LogosFreeResponseFnAbi* = proc(p: pointer) {.capi.}

  ## Setter for the call-module callback
  LogosSetCallModuleFnAbi* = proc(
    fn: LogosCallModuleFnAbi, freeFn: LogosFreeResponseFnAbi, userData: pointer
  ) {.capi.}
