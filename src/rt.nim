# src/rt.nim
# Logos Runtime Control module — native C ABI per LOGOS-MODULE-INTERFACE.
#
# Module name is the flat "logos_runtime_control" (RUNTIME §9.3); the schema
# namespace is "logos.runtime_control"
# (RUNTIME §9.3). Exports the identity/lifecycle symbols, the provider
# symbols (_call_surface, _free, _dispatch), and the schema-derived
# per-method functions logos_logos_runtime_control_call_logos_runtime_control_<method>.
#
# Delegates to a process-wide Runtime instance (POC: single runtime). Every
# successful response carries a payload commitment computed at the boundary.

import results
import logos_core/abi_types
import logos_core/cbor_profile
import logos_core/call_surface
import logos_core/runtime
import logos_core/rt_types
import logos_core/payload_commitment
import logos_core/rc_cbor
from logos_core/commitment import namedSubtreeRoot
from logos_core/transport import PayloadCommitment

# ============================================================================
# Schema (namespace: logos.runtime_control)
# Imports the `logos.runtime` supporting schema (§9.2) and
# `logos.module_configuration` (LOGOS-MODULE-CONFIGURATION).
# ============================================================================

const rtSchemaRuntime* = """
; -- shared Runtime Types supporting schema (RUNTIME §9.2) --
logos.runtime.module_name = tstr .size (1..64)
logos.runtime.runtime_instance_id = tstr .size (1..128)
logos.runtime.module_instance_id = tstr .size (1..128)
logos.runtime.module_provider_id = tstr .size (1..128)
logos.runtime.route_id = tstr .size (1..128)
logos.runtime.module_state_assignment_id = tstr .size (1..128)
logos.runtime.module_instance_address = {
    runtime_instance_id: logos.runtime.runtime_instance_id,
    module_instance_id: logos.runtime.module_instance_id,
}
logos.runtime.module_provider_address = {
    ? runtime_instance_id: logos.runtime.runtime_instance_id,
    provider: logos.runtime.module_provider_id,
}
"""

const rtSchemaModuleConfig* = """
; -- Module Configuration Types supporting schema (CONFIGURATION) --
logos.module_configuration.schema_commitment = {
    commitment_model: "logos.commitment-model.2026-08",
    schema_root: bstr .size 32,
    schema_subtree_root: bstr .size 32,
    hash_profile: "logos.hash-profile.2026-08.choice-index",
    hash_suite: "logos.hash-suite.blake3-256",
}
logos.module_configuration.value_commitment = {
    schema_subtree_root: bstr .size 32,
    value_root: bstr .size 32,
}
logos.module_configuration.configuration_value =
    bstr .size (1..8388608)
logos.module_configuration.schema_binding = {
    document: tstr .size (1..1048576),
    root: tstr .size (1..255),
    schema_commitment: logos.module_configuration.schema_commitment,
    ? live_reconfiguration: true,
}
logos.module_configuration.provenance =
    "package-default" /
    "protected-provisioning" /
    "runtime-control-update"
logos.module_configuration.value_record = {
    value: logos.module_configuration.configuration_value,
    schema_commitment: logos.module_configuration.schema_commitment,
    value_commitment: logos.module_configuration.value_commitment,
    value_revision: uint64,
    provenance: logos.module_configuration.provenance,
}
logos.module_configuration.value_record_metadata = {
    schema_commitment: logos.module_configuration.schema_commitment,
    value_commitment: logos.module_configuration.value_commitment,
    value_revision: uint64,
    provenance: logos.module_configuration.provenance,
}
logos.module_configuration.configuration_state = {
    state_revision: uint64,
    schema_commitment: logos.module_configuration.schema_commitment,
    ? current: logos.module_configuration.value_record,
    ? staged: logos.module_configuration.value_record,
}
logos.module_configuration.configuration_state_summary = {
    state_revision: uint64,
    schema_commitment: logos.module_configuration.schema_commitment,
    ? current: logos.module_configuration.value_record_metadata,
    ? staged: logos.module_configuration.value_record_metadata,
}
"""

## The `logos_runtime_control` module's PRIMARY schema document: only the
## `logos.runtime_control` declarations plus the `_module` marker. The shared
## Runtime Types and Module Configuration Types are separately supplied
## supporting schemas (INTERFACE §2.6), and the pinned `logos.schema_commitment`
## common type is NOT re-declared here (it resolves via the pinned registry as
## an imported reference) — so the derived namespace is `logos.runtime_control`,
## not the collapsed `logos` (I1).
const rtSchemaPrimary* = """
; -- metadata --
_module = "logos_runtime_control"

; -- scalar types --
logos.runtime_control.reason = tstr .size (0..512)
logos.runtime_control.address_profile = tstr .size (1..128)
logos.runtime_control.decision_id = tstr .size (1..128)
logos.runtime_control.failure_code = tstr .size (1..64)
logos.runtime_control.host_name = tstr .size (1..255)
logos.runtime_control.port = uint16
logos.runtime_control.path = tstr .size (1..4096)
logos.runtime_control.server_name = tstr .size (1..255)
logos.runtime_control.alpn = tstr .size (1..255)

logos.runtime_control.state =
    "unloaded" / "loaded" / "ready" / "stopping" / "error"
logos.runtime_control.mode =
    "direct" / "local-transport" / "remote-transport"
logos.runtime_control.route_state =
    "establishing" / "ready" / "draining" / "revoked" / "failed" / "closed"

; -- runtime addresses --
logos.runtime_control.unix_stream_runtime_address = {
    transport: "unix-stream",
    path: logos.runtime_control.path,
    ? profile: logos.runtime_control.address_profile,
}
logos.runtime_control.tls_tcp_runtime_address = {
    transport: "tls-tcp",
    host: logos.runtime_control.host_name,
    port: logos.runtime_control.port,
    ? server_name: logos.runtime_control.server_name,
    ? profile: logos.runtime_control.address_profile,
}
logos.runtime_control.quic_runtime_address = {
    transport: "quic",
    host: logos.runtime_control.host_name,
    port: logos.runtime_control.port,
    ? server_name: logos.runtime_control.server_name,
    ? alpn: logos.runtime_control.alpn,
    ? profile: logos.runtime_control.address_profile,
}
logos.runtime_control.runtime_address =
    logos.runtime_control.unix_stream_runtime_address /
    logos.runtime_control.tls_tcp_runtime_address /
    logos.runtime_control.quic_runtime_address
logos.runtime_control.runtime_endpoint = {
    ? runtime_instance_id: logos.runtime.runtime_instance_id,
    address: logos.runtime_control.runtime_address,
}

; -- remote records --
logos.runtime_control.remote_identity_profile =
    "logos.remote.tls-tcp" / "logos.remote.quic"
logos.runtime_control.trust_anchor_id = bstr .size (1..128)
logos.runtime_control.subject_public_key_info = bstr .size (1..8192)
logos.runtime_control.remote_runtime_enrollment =
    {
        runtime_instance_id: logos.runtime.runtime_instance_id,
        profile: logos.runtime_control.remote_identity_profile,
        revision: uint64,
        status: "active",
        trust_anchor: logos.runtime_control.trust_anchor_id,
        subject_public_keys: [logos.runtime_control.subject_public_key_info],
    } /
    {
        runtime_instance_id: logos.runtime.runtime_instance_id,
        profile: logos.runtime_control.remote_identity_profile,
        revision: uint64,
        status: "revoked",
    }
logos.runtime_control.remote_listener_address =
    logos.runtime_control.tls_tcp_runtime_address /
    logos.runtime_control.quic_runtime_address
logos.runtime_control.remote_listener_record = {
    address: logos.runtime_control.remote_listener_address,
    enabled: bool,
    runtime_control_enabled: bool,
}
logos.runtime_control.provider_export_record = {
    listener: logos.runtime_control.remote_listener_address,
    provider: logos.runtime.module_provider_address,
    enabled: bool,
}
logos.runtime_control.remote_provider_target = {
    runtime: logos.runtime_control.runtime_endpoint,
    ? provider: logos.runtime.module_provider_id,
    ? module: logos.runtime.module_name,
}

; -- core records --
logos.runtime_control.module_record = {
    module: logos.runtime.module_name,
    ? provider: logos.runtime.module_provider_address,
    ? remote: logos.runtime_control.remote_provider_target,
    ? instance: logos.runtime.module_instance_id,
    ? state_assignment: logos.runtime.module_state_assignment_id,
    state: logos.runtime_control.state,
    mode: logos.runtime_control.mode,
    ? primary_contract: logos.schema_commitment,
    ? implements: [* logos.schema_commitment],
    ? reason: logos.runtime_control.reason,
}
logos.runtime_control.invocation_descriptor =
    {
        kind: "local-transport",
        profile: "logos.local.unix-stream",
        path: logos.runtime_control.path,
        ticket: bstr .size 32,
    } /
    {
        kind: "remote-transport",
        runtime: logos.runtime.runtime_instance_id,
        provider: logos.runtime.module_provider_id,
        endpoint: logos.runtime_control.remote_listener_address,
        ticket: bstr .size 32,
    }
logos.runtime_control.route_failure = {
    code: logos.runtime_control.failure_code,
    ? message: logos.runtime_control.reason,
}
logos.runtime_control.route_access = {
    ? methods: [* bstr .size 32],
    ? publish_events: [* bstr .size 32],
    ? subscribe_events: [* bstr .size 32],
}
logos.runtime_control.provider_requirement_cardinality =
    "single" / "all-runtime-visible"
logos.runtime_control.route_record = {
    route: logos.runtime.route_id,
    consumer: logos.runtime.module_instance_address,
    target_provider: logos.runtime.module_provider_address,
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
    ? expected_contract: logos.schema_commitment,
    access: logos.runtime_control.route_access,
    state: logos.runtime_control.route_state,
    ? invocation: logos.runtime_control.invocation_descriptor,
    ? decision_id: logos.runtime_control.decision_id,
    ? expires_at: uint64,
    ? failure: logos.runtime_control.route_failure,
}

; -- methods --
logos.runtime_control.establish_route_request = {
    request_key: tstr .size (1..128),
    contract: logos.schema_commitment,
    cardinality: logos.runtime_control.provider_requirement_cardinality,
    ? provider: logos.runtime.module_provider_address,
    access: logos.runtime_control.route_access,
}
logos.runtime_control.establish_route_response = {
    routes: [* logos.runtime_control.route_record],
    partial: bool,
}
logos.runtime_control.renew_route_request = {
    request_key: tstr .size (1..128),
    route: logos.runtime.route_id,
}
logos.runtime_control.renew_route_response = {
    route: logos.runtime_control.route_record,
}
logos.runtime_control.list_modules_request = {}
logos.runtime_control.list_modules_response = {
    modules: [* logos.runtime_control.module_record],
    partial: bool,
}
logos.runtime_control.list_routes_request = {
    ? module: logos.runtime.module_name,
    ? provider: logos.runtime.module_provider_address,
}
logos.runtime_control.list_routes_response = {
    routes: [* logos.runtime_control.route_record],
    partial: bool,
}
logos.runtime_control.list_remote_listeners_request = {}
logos.runtime_control.list_remote_listeners_response = {
    listeners: [* logos.runtime_control.remote_listener_record],
    partial: bool,
}
logos.runtime_control.set_remote_listener_request = {
    listener: logos.runtime_control.remote_listener_record,
}
logos.runtime_control.set_remote_listener_response = {
    listener: logos.runtime_control.remote_listener_record,
}
logos.runtime_control.list_provider_exports_request = {
    ? listener: logos.runtime_control.remote_listener_address,
    ? provider: logos.runtime.module_provider_address,
}
logos.runtime_control.list_provider_exports_response = {
    exports: [* logos.runtime_control.provider_export_record],
    partial: bool,
}
logos.runtime_control.set_provider_export_request = {
    export: logos.runtime_control.provider_export_record,
}
logos.runtime_control.set_provider_export_response = {
    export: logos.runtime_control.provider_export_record,
}
logos.runtime_control.close_route_request = {
    route: logos.runtime.route_id,
    ? reason: logos.runtime_control.reason,
}
logos.runtime_control.close_route_response = {
    route: logos.runtime.route_id,
    state: logos.runtime_control.route_state,
}
logos.runtime_control.start_module_request = {
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
}
logos.runtime_control.start_module_response = {
    module: logos.runtime.module_name,
    instance: logos.runtime.module_instance_id,
    state: logos.runtime_control.state,
}
logos.runtime_control.stop_module_request = {
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
}
logos.runtime_control.stop_module_response = {
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
    state: logos.runtime_control.state,
}
logos.runtime_control.get_readiness_request = {
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
}
logos.runtime_control.get_readiness_response = {
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
    state: logos.runtime_control.state,
    ? reason: logos.runtime_control.reason,
}
logos.runtime_control.get_configuration_schema_request = {
    target: logos.runtime.module_instance_address,
}
logos.runtime_control.get_configuration_schema_response = {
    target: logos.runtime.module_instance_address,
    state_revision: uint64,
    schema: logos.module_configuration.schema_binding,
}
logos.runtime_control.get_configuration_request = {
    target: logos.runtime.module_instance_address,
}
logos.runtime_control.get_configuration_response = {
    target: logos.runtime.module_instance_address,
    state: logos.module_configuration.configuration_state,
}
logos.runtime_control.update_configuration_request =
    {
        target: logos.runtime.module_instance_address,
        expected_state_revision: uint64,
        expected_schema_commitment: logos.module_configuration.schema_commitment,
        action: "stage",
        value: logos.module_configuration.configuration_value,
    } /
    {
        target: logos.runtime.module_instance_address,
        expected_state_revision: uint64,
        expected_schema_commitment: logos.module_configuration.schema_commitment,
        action: "discard",
    }
logos.runtime_control.update_configuration_response = {
    target: logos.runtime.module_instance_address,
    state_revision: uint64,
    ? staged: logos.module_configuration.value_record,
}
logos.runtime_control.apply_configuration_request = {
    target: logos.runtime.module_instance_address,
    expected_state_revision: uint64,
}
logos.runtime_control.apply_configuration_response = {
    target: logos.runtime.module_instance_address,
    state_revision: uint64,
    applied_value_revision: uint64,
}

; -- events --
logos.runtime_control.configuration_state_changed_event = {
    target: logos.runtime.module_instance_address,
    state: logos.module_configuration.configuration_state_summary,
}
logos.runtime_control.module_state_changed_event = {
    module: logos.runtime.module_name,
    ? instance: logos.runtime.module_instance_id,
    old_state: logos.runtime_control.state,
    new_state: logos.runtime_control.state,
    ? reason: logos.runtime_control.reason,
}
logos.runtime_control.route_state_changed_event = {
    route: logos.runtime.route_id,
    old_state: logos.runtime_control.route_state,
    new_state: logos.runtime_control.route_state,
    ? module: logos.runtime.module_name,
    ? provider: logos.runtime.module_provider_address,
    ? reason: logos.runtime_control.reason,
}
"""

## Backwards-compatible alias for the primary document.
const rtSchema* = rtSchemaPrimary

## The primary document's separately supplied supporting schemas, in canonical
## (namespace-bytes) order (INTERFACE §2.6, I1). The pinned
## `logos.schema_commitment` common type is NOT listed here: it resolves via
## the pinned common-schema registry as an imported reference.
const rtSupportingDocs* = [
  ("logos.module_configuration", rtSchemaModuleConfig),
  ("logos.runtime", rtSchemaRuntime),
]

const moduleName* = "logos_runtime_control"
const rcNamespace* = "logos.runtime_control"

# ============================================================================
# Process-wide runtime (POC: single instance; context is a live marker)
# ============================================================================

## Per-instance module context: holds the pointer to the owning Runtime,
## set in logos_logos_runtime_control_init from the rcBinding.state field. Storing it in the ABI
## opaque context (not a process global) avoids use-after-free after the
## owning Runtime is destroyed, cross-instance overwrite, and unsynchronized
## cross-thread access (N7).
type RtModuleContext = object
  runtime: ptr Runtime

proc runtimeOf(module: LogosModuleContext): ptr Runtime =
  if module == nil:
    return nil
  cast[ptr RtModuleContext](module)[].runtime

## N1: the consumer bound to this RC module instance. Derived from the owning
## runtime's bootstrap identity (the host) — an authenticated consumer, not a
## fabricated module instance (retires the old pocConsumer). The consumer is
## derived at call time from the runtime pointer (not stored in the raw ABI
## context, which must not hold GC-managed strings).
proc consumerOf(module: LogosModuleContext): ModuleInstanceAddress =
  let rt = runtimeOf(module)
  if rt == nil:
    return ModuleInstanceAddress()
  ModuleInstanceAddress(
    runtimeInstanceId: rt[].runtimeInstanceId, moduleInstanceId: rt[].runtimeInstanceId
  )

# ============================================================================
# Commitment helpers (computed at the boundary, INTERFACE §5.1 / §2.7)
# ============================================================================

## Compute the payload commitment for a method response: the schema subtree
## root of the response declaration + the value root of the concrete value.
## The payload CBOR builders/parsers live in logos_core/rc_cbor.nim.
proc responseCommitment(
    meth: string, resp: CborValue
): Result[PayloadCommitment, string] =
  let respDecl = rcNamespace & "." & meth & "_response"
  computePayloadCommitment(rtSchema, respDecl, resp, rtSupportingDocs)

# ============================================================================
# Method logic (shared by _dispatch and the per-method functions)
# Each returns the response CBOR + the LogosResult. On success the response
# carries a payload commitment computed at the boundary.
# ============================================================================

proc withCommitment(meth: string, resp: CborValue): (CborValue, LogosResult) =
  ## Wrap a successful response with its payload commitment (INTERFACE §2.7).
  let pc = responseCommitment(meth, resp)
  if pc.isErr:
    return (resp, LogosResult(code: LOGOS_ERR_MODULE, message: pc.error.cstring))
  var pairs: seq[(CborValue, CborValue)] = @[]
  # The response map already has its fields; the commitment is added by the
  # transport envelope (POC: the method response is the bare value).
  discard pairs
  (resp, LogosResult(code: LOGOS_OK, message: nil))

proc rtNotInit(): (CborValue, LogosResult) =
  (
    cborNull(),
    LogosResult(code: LOGOS_ERR_MODULE, message: "runtime not initialized".cstring),
  )

## A request that failed to parse into its typed shape (INTERFACE §2.7).
proc badParams(msg: string): (CborValue, LogosResult) =
  (cborNull(), LogosResult(code: LOGOS_ERR_INVALID_PARAMS, message: msg.cstring))

proc doListModules(
    rt: ptr Runtime, consumer: ModuleInstanceAddress
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  let resp = rt[].listModules(consumer)
  if resp.isErr:
    return
      (cborNull(), LogosResult(code: LOGOS_ERR_MODULE, message: resp.error.cstring))
  withCommitment("list_modules", listModulesResponseCbor(resp.get))

proc doListRoutes(
    rt: ptr Runtime, consumer: ModuleInstanceAddress, req: CborValue
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  let lr = fromCborListRoutesRequest(req)
  if lr.isErr:
    return badParams(lr.error)
  let resp = rt[].listRoutes(consumer, lr.get)
  if resp.isErr:
    return
      (cborNull(), LogosResult(code: LOGOS_ERR_MODULE, message: resp.error.cstring))
  withCommitment("list_routes", listRoutesResponseCbor(resp.get))

proc doCloseRoute(
    rt: ptr Runtime, consumer: ModuleInstanceAddress, req: CborValue
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  let cr = fromCborCloseRouteRequest(req)
  if cr.isErr:
    return badParams(cr.error)
  let res = rt[].closeRoute(consumer, cr.get)
  if res.isErr:
    return (
      cborNull(),
      LogosResult(code: LOGOS_ERR_METHOD_NOT_FOUND, message: res.error.cstring),
    )
  withCommitment("close_route", closeRouteResponseCbor(res.get))

proc doEstablishRoute(
    rt: ptr Runtime, consumer: ModuleInstanceAddress, req: CborValue
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  # Parse the request into its typed shape (RUNTIME §9.3): request_key,
  # contract, cardinality, optional provider, and the route_access scope.
  let er = fromCborEstablishRouteRequest(req)
  if er.isErr:
    return badParams(er.error)
  let res = rt[].establishRoute(consumer, er.get)
  if res.isErr:
    return (cborNull(), LogosResult(code: LOGOS_ERR_MODULE, message: res.error.cstring))
  withCommitment("establish_route", establishRouteResponseCbor(res.get))

proc doStartModule(
    rt: ptr Runtime, consumer: ModuleInstanceAddress, req: CborValue
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  let sm = fromCborStartModuleRequest(req)
  if sm.isErr:
    return badParams(sm.error)
  let res = rt[].startModule(consumer, sm.get)
  if res.isErr:
    return (cborNull(), LogosResult(code: LOGOS_ERR_MODULE, message: res.error.cstring))
  withCommitment("start_module", startModuleResponseCbor(res.get))

proc doStopModule(
    rt: ptr Runtime, consumer: ModuleInstanceAddress, req: CborValue
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  let sm = fromCborStopModuleRequest(req)
  if sm.isErr:
    return badParams(sm.error)
  let res = rt[].stopModule(consumer, sm.get)
  if res.isErr:
    return (cborNull(), LogosResult(code: LOGOS_ERR_MODULE, message: res.error.cstring))
  withCommitment("stop_module", stopModuleResponseCbor(res.get))

proc doGetReadiness(
    rt: ptr Runtime, consumer: ModuleInstanceAddress, req: CborValue
): (CborValue, LogosResult) =
  if rt == nil:
    return rtNotInit()
  let gr = fromCborGetReadinessRequest(req)
  if gr.isErr:
    return badParams(gr.error)
  let res = rt[].getReadiness(consumer, gr.get)
  if res.isErr:
    # report state "error" in a successful response (INTERFACE §2.7), echoing
    # back the requested module/instance
    let v = getReadinessResponseCbor(
      GetReadinessResponse(
        module: gr.get.module,
        instance: gr.get.instance,
        state: msError,
        reason: Opt.some(res.error),
      )
    )
    return withCommitment("get_readiness", v)
  withCommitment("get_readiness", getReadinessResponseCbor(res.get))

# ============================================================================
# Identity and lifecycle symbols
# ============================================================================

proc logos_logos_runtime_control_name(): cstring {.exportc, dynlib.} =
  moduleName.cstring

proc logos_logos_runtime_control_init(
    input: ptr LogosModuleInitInput, outContext: ptr LogosModuleContext
): LogosResult {.exportc, dynlib.} =
  if input.abiVersion != LOGOS_MODULE_INIT_ABI_VERSION:
    return LogosResult(
      code: LOGOS_ERR_VERSION_MISMATCH, message: "unsupported ABI version".cstring
    )
  if input.structSize < sizeof(LogosModuleInitInput).csize_t:
    return LogosResult(
      code: LOGOS_ERR_VERSION_MISMATCH,
      message: "initialization struct too small".cstring,
    )
  # Locate the owning Runtime from the rcBinding.state pointer and store it
  # in the per-instance context (N7: not a process global).
  var rt: ptr Runtime
  if input.runtimeControl != nil and input.runtimeControl.state != nil:
    rt = cast[ptr ptr Runtime](input.runtimeControl.state)[]
  let ctx = cast[LogosModuleContext](alloc(sizeof(RtModuleContext)))
  cast[ptr RtModuleContext](ctx)[].runtime = rt
  outContext[] = ctx
  LogosResult(code: LOGOS_OK, message: nil)

proc logos_logos_runtime_control_destroy(
    module: LogosModuleContext
) {.exportc, dynlib.} =
  if module != nil:
    dealloc(module)

# ============================================================================
# Provider symbols
# ============================================================================

## The call-surface descriptor is built once and returned as the same static
## bytes on every call (INTERFACE §2.6 "MUST return the same bytes on every");
## the caller MUST NOT free it (§2.7), so the buffer lives for the process.
var cachedRtSurface: ptr uint8 = nil
var cachedRtSurfaceLen: csize_t = 0

proc logos_logos_runtime_control_call_surface(
    outLen: ptr csize_t
): ptr uint8 {.exportc, dynlib.} =
  if cachedRtSurface == nil:
    # The primary document is `logos.runtime_control` only; the shared
    # Runtime Types and Module Configuration Types are separately supplied
    # supporting schemas (INTERFACE §2.6), in canonical namespace order
    # (`logos.module_configuration` < `logos.runtime`). The pinned
    # `logos.schema_commitment` is NOT re-declared (I1).
    let desc = buildCallSurface(
      rtSchemaPrimary,
      @[
        ("logos.module_configuration", rtSchemaModuleConfig),
        ("logos.runtime", rtSchemaRuntime),
      ],
      @[],
    )
    cachedRtSurface = cast[ptr uint8](alloc0(desc.len))
    copyMem(cachedRtSurface, addr desc[0], desc.len)
    cachedRtSurfaceLen = desc.len.csize_t
  outLen[] = cachedRtSurfaceLen
  cachedRtSurface

proc logos_logos_runtime_control_free(
    module: LogosModuleContext, p: pointer
) {.exportc, dynlib.} =
  discard module
  if p != nil:
    deallocShared(p)

proc dispatchMethod(
    rt: ptr Runtime,
    consumer: ModuleInstanceAddress,
    methodName: string,
    params: CborValue,
): (CborValue, LogosResult) =
  ## Route a bare method name to its handler. `logos.schema` is handled at
  ## the boundary (introspection, never forwarded to a provider). The consumer
  ## is bound to the RC module instance (N1: not a process-global value).
  if rt == nil:
    return (
      cborNull(),
      LogosResult(code: LOGOS_ERR_MODULE, message: "runtime not initialized".cstring),
    )
  case methodName
  of "logos.schema":
    # selected-contract introspection at the boundary (RUNTIME §9.3):
    # returns a logos.schema_response map (INTERFACE §5.1) carrying the
    # primary schema document. (The supporting schemas are inlined in the
    # POC document; separating them is tracked as I1.)
    (
      cborMap((cborValue("schema"), cborValue(rtSchema))),
      LogosResult(code: LOGOS_OK, message: nil),
    )
  of "list_modules":
    doListModules(rt, consumer)
  of "list_routes":
    doListRoutes(rt, consumer, params)
  of "establish_route":
    doEstablishRoute(rt, consumer, params)
  of "renew_route":
    (
      cborNull(),
      LogosResult(code: LOGOS_ERR_NOT_READY, message: "renew_route not ready".cstring),
    )
  of "close_route":
    doCloseRoute(rt, consumer, params)
  of "start_module":
    doStartModule(rt, consumer, params)
  of "stop_module":
    doStopModule(rt, consumer, params)
  of "get_readiness":
    doGetReadiness(rt, consumer, params)
  of "list_remote_listeners", "list_provider_exports":
    (
      cborNull(),
      LogosResult(
        code: LOGOS_ERR_NOT_READY, message: "remote ops not ready (Phase 5)".cstring
      ),
    )
  of "set_remote_listener", "set_provider_export":
    (
      cborNull(),
      LogosResult(
        code: LOGOS_ERR_NOT_READY, message: "remote ops not ready (Phase 5)".cstring
      ),
    )
  of "get_configuration_schema", "get_configuration", "update_configuration",
      "apply_configuration":
    (
      cborNull(),
      LogosResult(
        code: LOGOS_ERR_NOT_READY, message: "configuration not ready (Phase 5)".cstring
      ),
    )
  else:
    (
      cborNull(),
      LogosResult(code: LOGOS_ERR_METHOD_NOT_FOUND, message: "unknown method".cstring),
    )

proc logos_logos_runtime_control_dispatch(
    module: LogosModuleContext,
    methodName: cstring,
    paramsCbor: ptr uint8,
    paramsLen: csize_t,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  let consumer = consumerOf(module)
  var params: CborValue = cborNull()
  if paramsLen > 0 and paramsCbor != nil:
    var payload = newSeq[byte](paramsLen)
    copyMem(addr payload[0], paramsCbor, paramsLen)
    params = decodeCbor(payload)
  var (resp, res) = dispatchMethod(rt, consumer, $methodName, params)
  if res.code == LOGOS_OK:
    let bytes = encodeCbor(resp)
    let buf = cast[ptr uint8](allocShared(bytes.len))
    copyMem(buf, addr bytes[0], bytes.len)
    outResponseCbor[] = buf
    outResponseLen[] = bytes.len.csize_t
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
  res

# ============================================================================
# Schema-derived per-method functions
# ============================================================================

proc callAndReturn(
    resp: CborValue, outResponseCbor: ptr ptr uint8, outResponseLen: ptr csize_t
): LogosResult =
  let bytes = encodeCbor(resp)
  let buf = cast[ptr uint8](allocShared(bytes.len))
  copyMem(buf, addr bytes[0], bytes.len)
  outResponseCbor[] = buf
  outResponseLen[] = bytes.len.csize_t
  LogosResult(code: LOGOS_OK, message: nil)

proc failNotReady(
    outResponseCbor: ptr ptr uint8, outResponseLen: ptr csize_t
): LogosResult =
  outResponseCbor[] = nil
  outResponseLen[] = 0
  LogosResult(code: LOGOS_ERR_NOT_READY, message: "not ready".cstring)

proc logos_logos_runtime_control_call_logos_runtime_control_list_modules(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  let (resp, res) = doListModules(rt, consumerOf(module))
  if res.code == LOGOS_OK:
    callAndReturn(resp, outResponseCbor, outResponseLen)
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    res

proc logos_logos_runtime_control_call_logos_runtime_control_list_routes(
    module: LogosModuleContext,
    inModule: ptr cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  var params: CborValue = cborNull()
  if inModule != nil and $inModule[] != "":
    params = cborMap((cborValue("module"), cborValue($inModule[])))
  let (resp, res) = doListRoutes(rt, consumerOf(module), params)
  if res.code == LOGOS_OK:
    callAndReturn(resp, outResponseCbor, outResponseLen)
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    res

proc logos_logos_runtime_control_call_logos_runtime_control_close_route(
    module: LogosModuleContext,
    inRoute: cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  let params = cborMap((cborValue("route"), cborValue($inRoute)))
  let (resp, res) = doCloseRoute(rt, consumerOf(module), params)
  if res.code == LOGOS_OK:
    callAndReturn(resp, outResponseCbor, outResponseLen)
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    res

proc logos_logos_runtime_control_call_logos_runtime_control_start_module(
    module: LogosModuleContext,
    inModule: cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  let params = cborMap((cborValue("module"), cborValue($inModule)))
  let (resp, res) = doStartModule(rt, consumerOf(module), params)
  if res.code == LOGOS_OK:
    callAndReturn(resp, outResponseCbor, outResponseLen)
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    res

proc logos_logos_runtime_control_call_logos_runtime_control_stop_module(
    module: LogosModuleContext,
    inModule: cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  let params = cborMap((cborValue("module"), cborValue($inModule)))
  let (resp, res) = doStopModule(rt, consumerOf(module), params)
  if res.code == LOGOS_OK:
    callAndReturn(resp, outResponseCbor, outResponseLen)
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    res

proc logos_logos_runtime_control_call_logos_runtime_control_get_readiness(
    module: LogosModuleContext,
    inModule: cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  let rt = runtimeOf(module)
  let params = cborMap((cborValue("module"), cborValue($inModule)))
  let (resp, res) = doGetReadiness(rt, consumerOf(module), params)
  if res.code == LOGOS_OK:
    callAndReturn(resp, outResponseCbor, outResponseLen)
  else:
    outResponseCbor[] = nil
    outResponseLen[] = 0
    res

proc logos_logos_runtime_control_call_logos_runtime_control_establish_route(
    module: LogosModuleContext,
    inRequestKey: cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  discard inRequestKey
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_renew_route(
    module: LogosModuleContext,
    inRequestKey: cstring,
    inRoute: cstring,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  discard inRequestKey
  discard inRoute
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_list_remote_listeners(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_set_remote_listener(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_list_provider_exports(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_set_provider_export(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_get_configuration_schema(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_get_configuration(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_update_configuration(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)

proc logos_logos_runtime_control_call_logos_runtime_control_apply_configuration(
    module: LogosModuleContext,
    outResponseCbor: ptr ptr uint8,
    outResponseLen: ptr csize_t,
): LogosResult {.exportc, dynlib.} =
  discard module
  failNotReady(outResponseCbor, outResponseLen)
