# src/logos_core/high_level.nim
# High-level Nim-friendly types for the Logos module interface.
# Wraps C ABI types with convenience conversions (cstring→string, pointer/len→seq[byte]).

import results, ./abi_types, ./rt_types

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
  ModuleName, RuntimeInstanceId, ModuleProviderId, ModuleInstanceId, SchemaNamespace
export RouteId, DescriptorKind, AuthorityRef, AuditRef, HostName, Port, Path
export ServerName, Alpn, AddressProfile, FailureCode, Reason, SchemaModel
export RuntimeAddressTag, UnixStreamAddress, TcpAddress, TlsTcpAddress, QuicAddress
export RuntimeAddress, RuntimeEndpoint, RemoteProviderTarget, ModuleProviderAddress
export SchemaCommitment
export ModuleState, ModuleMode, RouteState
export InvocationDescriptor, RouteAuthority, RouteFailure, ModuleRecord, RouteRecord

## String conversion helpers
export
  stateName, modeName, routeStateName, stringToModuleState, stringToModuleMode,
  stringToRouteState

# ============================================================================
# High-level function types
# These are Nim-proc-style wrappers around the C ABI function pointers.
# ============================================================================

type
  ## Lifecycle _init — returns 0 on success, non-zero error code
  InitFn* = proc(): cint {.api.}

  ## Lifecycle destroy
  DestroyFn* = proc() {.api.}

  ## Module memory deallocator
  FreeFn* = proc(p: pointer) {.api.}

  ## High-level dispatch — takes a method name and CBOR bytes, returns a Result of
  ## CBOR bytes.
  DispatchFn* =
    proc(meth: string, params: openArray[byte]): Result[seq[byte], string] {.api.}

  ## Event publishing
  PublishFn* = proc(eventData: seq[byte]) {.api.}

  ## Setter for the high-level publish callback
  PublishSetter* = proc(fn: PublishFn, userData: pointer) {.api.}

  ## High-level call-module callback — takes target name and request bytes,
  ## returns a Result with the response bytes.
  CallModuleFn* = proc(
    targetModule: string, requestCbor: openArray[byte]
  ): Result[seq[byte], string] {.api.}

  ## Response deallocator for call-module
  FreeResponseFn* = proc(p: pointer) {.api.}

  ## Setter for the high-level call-module callback
  CallModuleSetter* =
    proc(fn: CallModuleFn, freeFn: FreeResponseFn, userData: pointer) {.api.}

  ## A loaded Logos module at the high-level Nim API.
  ## Holds the module metadata and the high-level dispatch function.
  ## The actual FFI bridges are created by wrapDispatchFn etc.
  Module* = object
    name*: string
    host*: string
    version*: string
    schema*: string

    ## Mandatory lifecycle
    initFn*: InitFn
    destroyFn*: DestroyFn

    dispatchFn*: DispatchFn
    freeFn*: FreeFn

    ## Optional callbacks (may be nil if module doesn't publish or call modules)
    publishSetter*: Opt[PublishSetter]
    callModuleSetter*: Opt[CallModuleSetter]
