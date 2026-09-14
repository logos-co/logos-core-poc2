# src/logos_core/high_level.nim
# High-level Nim-friendly types for the Logos module interface.
# Wraps C ABI types with convenience conversions (cstring→string, pointer/len→seq[byte]).

import results, ./abi_types, ./rt_types, ./shared_modules, ./transport

# ============================================================================
# Reexports — types that are identical at ABI and high-level
# ============================================================================

export
  LOGOS_OK, LOGOS_ERR_METHOD_NOT_FOUND, LOGOS_ERR_INVALID_PARAMS, LOGOS_ERR_MODULE,
  LOGOS_ERR_NOT_AUTHORISED, LOGOS_ERR_TRANSPORT, LOGOS_ERR_TIMEOUT,
  LOGOS_ERR_VERSION_MISMATCH, LOGOS_ERR_NOT_READY, LOGOS_ERR_CANCELLED

{.pragma: api, raises: [], gcsafe.}

# ============================================================================
# Runtime Control re-exports
# From LOGOS-MODULE-RUNTIME Section 9.1 — imported from rt_types.nim
# ============================================================================

export
  ModuleName, RuntimeInstanceId, ModuleProviderId, ModuleInstanceId, RouteId,
  ModuleStateAssignmentId
export ModuleInstanceAddress, ModuleProviderAddress
export Reason, AddressProfile, DecisionId, FailureCode, HostName, Port, Path
export ServerName, Alpn, TrustAnchorId, SubjectPublicKeyInfo
export ModuleState, ModuleMode, RouteState
export RuntimeAddressKind, UnixStreamRuntimeAddress, TlsTcpRuntimeAddress
export QuicRuntimeAddress, RuntimeAddress, RuntimeEndpoint, RemoteProviderTarget
export RemoteListenerAddress
export RemoteIdentityProfile, RemoteRuntimeEnrollment, RemoteListenerRecord
export ProviderExportRecord
export SchemaCommitment
export InvocationDescriptor, RouteFailure, RouteAccess, ModuleRecord, RouteRecord
export EstablishRouteRequest, EstablishRouteResponse, RenewRouteRequest
export RenewRouteResponse, ListModulesRequest, ListModulesResponse
export ListRoutesRequest, ListRoutesResponse, CloseRouteRequest
export CloseRouteResponse, StartModuleRequest, StartModuleResponse
export StopModuleRequest, StopModuleResponse, GetReadinessRequest
export GetReadinessResponse, ModuleStateChangedEvent, RouteStateChangedEvent

## String conversion helpers
export stateName, modeName, routeStateName, isTerminalRouteState

# ============================================================================
# High-level function types
# These are Nim-proc-style wrappers around the C ABI function pointers.
# ============================================================================

type
  ## High-level lifecycle bridge: create one instance (0 on success, non-zero
  ## error code). Closures in runtime.nim drive the new-ABI _init.
  InitFn* = proc(): cint {.api.}

  ## High-level lifecycle bridge: destroy this instance's context.
  DestroyFn* = proc() {.api.}

  ## High-level memory deallocator bridge (new-ABI _free(module, p)).
  FreeFn* = proc(p: pointer) {.api.}

  ## High-level dispatch bridge — takes a method name and deterministic-CBOR
  ## bytes, returns a Result of deterministic-CBOR bytes.
  DispatchFn* =
    proc(meth: string, params: openArray[byte]): Result[seq[byte], string] {.api.}

  ## A loaded Logos module at the high-level Nim API.
  ## The bridge closures (initFn/destroyFn/dispatchFn/freeFn) drive the new
  ## C ABI (Phase 2); the new-ABI state below is the source of truth.
  Module* = object
    name*: string
    host*: string
    version*: string
    schema*: string

    ## High-level lifecycle/dispatch bridges (closures over the new ABI)
    initFn*: InitFn
    destroyFn*: DestroyFn
    dispatchFn*: DispatchFn
    freeFn*: FreeFn

    ## New-ABI state (Phase 2): the loaded provider library, the
    ## per-instance context, and this instance's runtime-control binding.
    ## Nil for TCP-backed modules.
    shared*: ptr SharedModule
    ctx*: LogosModuleContext
    rcBinding*: ptr LogosRuntimeControlBinding
