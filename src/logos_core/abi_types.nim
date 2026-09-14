# src/logos_core/abi_types.nim
# C ABI types for the Logos module interface.
# Per LOGOS-MODULE-INTERFACE §2.6 (lifecycle symbols), §2.7 (memory
# management), §5.1/§5.2 (common schema surface, logos_types.h),
# LOGOS-MODULE-RUNTIME §8.1 (initialization inputs).
#
# The module context is opaque at the ABI boundary: both sides treat it
# as a `pointer`. The module implementation owns and defines it.

{.pragma: capi, cdecl, raises: [], gcsafe.}

# ============================================================================
# Error codes — the shared status registry (INTERFACE §5.1, values 0..9)
# ============================================================================

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

const
  LOGOS_ERROR_MESSAGE_MAX_LEN* = 512
  LOGOS_ERROR_DETAIL_MAX_LEN* = 4096

  LOGOS_MODULE_INIT_ABI_VERSION* = 1'u32
  LOGOS_RUNTIME_CONTROL_VTABLE_ABI_VERSION* = 1'u32
  LOGOS_ROUTE_VTABLE_ABI_VERSION* = 1'u32

  # provider-call-surface limits (INTERFACE §2.6)
  MaxCallSurfaceBytes* = 8388608
  MaxCallSurfaceInterfaces* = 256
  MaxSchemaDocumentBytes* = 1048576
  MaxSupportingNamespaceBytes* = 128

  # dynamic schema validation limits (INTERFACE §5.3)
  MaxSchemaSetBytes* = 8388608
  MaxSchemaNodes* = 65536
  MaxSchemaNesting* = 128

# ============================================================================
# Result (INTERFACE §5.2)
# ============================================================================

type
  ## Status of one ABI operation. `message` is NULL for LOGOS_OK; when
  ## non-null it holds at most LOGOS_ERROR_MESSAGE_MAX_LEN UTF-8 bytes
  ## and is valid until the next ABI call into the returning
  ## implementation on the calling thread (INTERFACE §2.7). `detail`
  ## holds at most LOGOS_ERROR_DETAIL_MAX_LEN bytes of one
  ## deterministic-CBOR value and is allowed only for
  ## LOGOS_ERR_INVALID_PARAMS (logos.invalid_params_detail).
  LogosResult* = object
    code*: cint
    message*: cstring
    detail*: ptr uint8
    detailLen*: csize_t

# ============================================================================
# Runtime Control binding and route handle (INTERFACE §5.2)
# ============================================================================

type
  ## Opaque per-instance module context, owned by the module.
  ## ABI callers never dereference or free it.
  LogosModuleContext* = pointer

  LogosSubscriptionId* = uint64

  ## Event handler for route-handle subscriptions (INTERFACE §5.2).
  LogosEventHandler* = proc(
    eventName: cstring, cborData: ptr uint8, cborDataLen: csize_t, userData: pointer
  ) {.capi.}

  ## Event publication callback supplied in the initialization input
  ## (INTERFACE §5.2). `user_data` is passed back unchanged.
  LogosPublishFn* = proc(
    userData: pointer, eventName: cstring, cborData: ptr uint8, cborDataLen: csize_t
  ) {.capi.}

  LogosRouteHandle* = object
    vtable*: ptr LogosRouteVtable
    state*: pointer

  LogosRuntimeControlVtable* = object
    abiVersion*: uint32
    structSize*: csize_t
    call*: proc(
      binding: ptr LogosRuntimeControlBinding,
      methodName: cstring,
      paramsCbor: ptr uint8,
      paramsCborLen: csize_t,
      outResponseCbor: ptr ptr uint8,
      outResponseCborLen: ptr csize_t,
    ): LogosResult
    releaseResponse*: proc(
      binding: ptr LogosRuntimeControlBinding,
      responseCbor: ptr uint8,
      responseCborLen: csize_t,
    )
    subscribe*: proc(
      binding: ptr LogosRuntimeControlBinding,
      eventName: cstring,
      handler: LogosEventHandler,
      userData: pointer,
      outSubscriptionId: ptr LogosSubscriptionId,
    ): LogosResult
    unsubscribe*: proc(
      binding: ptr LogosRuntimeControlBinding, subscriptionId: LogosSubscriptionId
    ): LogosResult
    materializeRoute*: proc(
      binding: ptr LogosRuntimeControlBinding,
      routeId: cstring,
      expectedContractRoot: ptr uint8,
      outRoute: ptr LogosRouteHandle,
    ): LogosResult

  LogosRuntimeControlBinding* = object
    vtable*: ptr LogosRuntimeControlVtable
    state*: pointer

  LogosRouteVtable* = object
    abiVersion*: uint32
    structSize*: csize_t
    call*: proc(
      route: ptr LogosRouteHandle,
      methodName: cstring,
      paramsCbor: ptr uint8,
      paramsCborLen: csize_t,
      outResponseCbor: ptr ptr uint8,
      outResponseCborLen: ptr csize_t,
    ): LogosResult
    releaseResponse*: proc(
      route: ptr LogosRouteHandle, responseCbor: ptr uint8, responseCborLen: csize_t
    )
    subscribe*: proc(
      route: ptr LogosRouteHandle,
      eventName: cstring,
      handler: LogosEventHandler,
      userData: pointer,
      outSubscriptionId: ptr LogosSubscriptionId,
    ): LogosResult
    unsubscribe*: proc(
      route: ptr LogosRouteHandle, subscriptionId: LogosSubscriptionId
    ): LogosResult
    release*: proc(route: ptr LogosRouteHandle)

# ============================================================================
# Structured initialization input (INTERFACE §5.2, RUNTIME §8.1)
# ============================================================================

type LogosModuleInitInput* = object
  abiVersion*: uint32
  structSize*: csize_t
  runtimeControl*: ptr LogosRuntimeControlBinding
  publishUserData*: pointer
  publish*: LogosPublishFn
  stateDir*: cstring
  configurationCbor*: ptr uint8
  configurationCborLen*: csize_t

# ============================================================================
# Module ABI function pointer types (INTERFACE §2.6)
# ============================================================================

type
  ## Module identity — static string, valid for the implementation-binding
  ## lifetime. MUST be called pre-init and match the expected name.
  LogosNameFn* = proc(): cstring {.capi.}

  ## Create one module instance from one structured initialization input.
  ## The caller sets `*outContext = nil` before the call.
  LogosInitFn* = proc(
    input: ptr LogosModuleInitInput, outContext: ptr LogosModuleContext
  ): LogosResult {.capi.}

  ## Optional standard ABI hook: apply one complete configuration to a
  ## live-reconfigurable module instance.
  LogosApplyConfigurationFn* = proc(
    module: LogosModuleContext,
    configurationCbor: ptr uint8,
    configurationCborLen: csize_t,
  ): LogosResult {.capi.}

  ## Destroy one successfully initialized module instance.
  LogosDestroyFn* = proc(module: LogosModuleContext) {.capi.}

  ## Provider-only: deterministic-CBOR call-surface descriptor.
  ## Returns immutable bytes valid for the implementation-binding lifetime.
  LogosCallSurfaceFn* = proc(outLen: ptr csize_t): ptr uint8 {.capi.}

  ## Provider-only: release dynamic values transferred by this module
  ## instance across the provider ABI. `free(module, nil)` is a no-op.
  LogosFreeFn* = proc(module: LogosModuleContext, p: pointer) {.capi.}

  ## Provider-only: generic deterministic-CBOR dispatch entrypoint.
  ## `method` is the bare schema method name; `paramsCbor` is the
  ## deterministic-CBOR request map (not a Transport envelope).
  LogosDispatchFn* = proc(
    module: LogosModuleContext,
    methodName: cstring,
    paramsCbor: ptr uint8,
    paramsLen: csize_t,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
  ): LogosResult {.capi.}
