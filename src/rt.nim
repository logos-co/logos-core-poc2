# src/rt.nim
# Logos Runtime Control Module
# Implements the runtime-control interface defined in LOGOS-MODULE-RUNTIME §9.1
# Delegates to a Runtime instance for actual operations

import
  std/tables,
  results,
  cbor_serialization,
  ./logos_core/[cbor_stuff, modules, runtime, rt_types, abi_types]

# ============================================================================
# Metadata
# ============================================================================

const
  moduleName = "rt"
  version = "1.0"
  schema = """
; -- metadata --
_module = "rt"
_version = [1, 0]

; -- types --
rt.state = "unloaded" / "loaded" / "ready" / "stopping" / "error"
rt.mode = "direct" / "local-transport" / "remote-transport"
rt.route_state = "establishing" / "ready" / "draining" / "revoked" / "failed" / "closed"

; -- method definitions --

; list_modules
rt.list_modules_request = {}
rt.list_modules_response = {
    modules: [* {
        module: tstr,
        ? provider: {
            ? runtime_instance_id: tstr,
            provider: tstr,
        },
        ? remote: {
            runtime: {
                ? runtime_instance_id: tstr,
                address: {
                    transport: tstr,
                    ? path: tstr,
                    ? host: tstr,
                    ? port: uint,
                    ? server_name: tstr,
                    ? alpn: tstr,
                },
            },
            ? provider: tstr,
            ? module: tstr,
        },
        ? instance: tstr,
        state: rt.state,
        mode: rt.mode,
        ? schema_namespace: tstr,
        ? schema: {
            commitment_model: tstr,
            schema_root: bstr,
            hash_profile: tstr,
            hash_suite: tstr,
        },
        ? reason: tstr,
    }],
}

; list_routes
rt.list_routes_request = {
    ? module: tstr,
    ? provider: {
        ? runtime_instance_id: tstr,
        provider: tstr,
    },
}
rt.list_routes_response = {
    routes: [* {
        route: tstr,
        caller_runtime: tstr,
        target_provider: {
            ? runtime_instance_id: tstr,
            provider: tstr,
        },
        module: tstr,
        ? instance: tstr,
        ? schema_namespace: tstr,
        ? schema: {
            commitment_model: tstr,
            schema_root: bstr,
            hash_profile: tstr,
            hash_suite: tstr,
        },
        state: rt.route_state,
        invocation: {
            kind: rt.mode,
            descriptor_kind: tstr,
            ? descriptor: bstr,
        },
        ? authority: {
            ? authority_provider: {
                ? runtime_instance_id: tstr,
                provider: tstr,
            },
            ? authority_ref: tstr,
            ? expires_at: uint,
            ? audit_ref: tstr,
        },
        ? failure: {
            code: tstr,
            ? message: tstr,
        },
    }],
}

; revoke_route
rt.revoke_route_request = {
    route: tstr,
    ? reason: tstr,
}
rt.revoke_route_response = {
    route: tstr,
    state: rt.route_state,
}

; start_module
rt.start_module_request = {
    module: tstr,
    ? instance: tstr,
}
rt.start_module_response = {
    module: tstr,
    instance: tstr,
    state: rt.state,
}

; stop_module
rt.stop_module_request = {
    module: tstr,
    ? instance: tstr,
}
rt.stop_module_response = {
    module: tstr,
    ? instance: tstr,
    state: rt.state,
}

; get_readiness
rt.get_readiness_request = {
    module: tstr,
    ? instance: tstr,
}
rt.get_readiness_response = {
    module: tstr,
    ? instance: tstr,
    state: rt.state,
    ? reason: tstr,
}
"""

# ============================================================================
# Global runtime instance (shared across all module calls)
# ============================================================================

# TODO instead of a global runtime, we should be using the context pointer
var gRuntime*: Runtime = Runtime(
  modules: initTable[string, ModuleInfo](), subscribers: @[], tcpHost: nil, routes: @[]
)

# ============================================================================
# Helper: Convert ModuleInfo to a ModuleRecordInline for CBOR encoding
# ============================================================================

func moduleInfoToRecordInline(info: ModuleInfo): ModuleRecordInline =
  ## Convert a runtime ModuleInfo into a ModuleRecordInline for CBOR serialization.
  ## Field names match CDDL exactly so Cbor.encode() produces the correct map.
  ModuleRecordInline(
    module: info.m.name,
    provider: Opt.none(ProviderAddressInline),
    remote: Opt.none(RemoteProviderInline),
    instance:
      if info.instanceId.len > 0:
        Opt.some(info.instanceId)
      else:
        Opt.none(ModuleInstanceId),
    state: info.state,
    mode: mmDirect,
    schema_namespace: Opt.none(SchemaNamespace),
    schema: Opt.none(SchemaCommitment),
    reason: Opt.none(Reason),
  )

# ============================================================================
# Request/Response CBOR decoding helpers
# ============================================================================

proc decodeString(payload: seq[byte], key: string): string =
  let map = Cbor.decode(payload, CborValueRef)
  if map.kind == CborValueKind.Object:
    for k, v in map.objVal.pairs:
      if k == key and v.kind == CborValueKind.String:
        return v.strVal
  ""

# ============================================================================
# Per-method C API implementations
# ============================================================================

proc logos_rt_call_list_modules(
    ctx: pointer, out_response: ptr ptr uint8, out_response_len: ptr csize_t
): cint {.exportc, dynlib.} =
  ## Build the response using the dedicated ListModulesResponse type and
  ## encode it directly with Cbor.encode(). Field names match CDDL exactly.
  var records: seq[ModuleRecordInline] = @[]
  for _, info in gRuntime.modules.pairs:
    records.add(info.moduleInfoToRecordInline())

  let response = ListModulesResponse(modules: records)
  let bytes = Cbor.encode(response)
  let buf = alloc(bytes.len)
  copyMem(buf, addr bytes[0], bytes.len)
  out_response[] = cast[ptr uint8](buf)
  out_response_len[] = bytes.len.csize_t
  LOGOS_OK

proc logos_rt_call_list_routes(
    ctx: pointer, out_response: ptr ptr uint8, out_response_len: ptr csize_t
): cint {.exportc, dynlib.} =
  ## Build the response using the dedicated ListRoutesResponse type and
  ## encode it directly with Cbor.encode().
  var records: seq[RouteRecordInline] = @[]
  for ri in gRuntime.routes:
    let route = ri.route
    let rec = RouteRecordInline(
      route: route.route,
      caller_runtime: route.caller_runtime,
      target_provider: route.target_provider,
      module: route.module,
      instance: route.instance,
      schema_namespace: route.schema_namespace,
      schema: route.schema,
      state: ri.state,
      invocation: route.invocation,
      authority: route.authority,
      failure: route.failure,
    )
    records.add(rec)

  let response = ListRoutesResponse(routes: records)
  let bytes = Cbor.encode(response)
  let buf = alloc(bytes.len)
  copyMem(buf, addr bytes[0], bytes.len)
  out_response[] = cast[ptr uint8](buf)
  out_response_len[] = bytes.len.csize_t
  LOGOS_OK

proc logos_rt_call_revoke_route(
    ctx: pointer,
    routeId: cstring,
    out_response: ptr ptr uint8,
    out_response_len: ptr csize_t,
): cint {.exportc, dynlib.} =
  let rid = $routeId
  for i in 0 ..< gRuntime.routes.len:
    if gRuntime.routes[i].route.route == rid:
      gRuntime.routes[i].state = rsRevoked
      let response = RevokeRouteResponse(route: rid, state: rsRevoked)
      let bytes = Cbor.encode(response)
      let buf = alloc(bytes.len)
      copyMem(buf, addr bytes[0], bytes.len)
      out_response[] = cast[ptr uint8](buf)
      out_response_len[] = bytes.len.csize_t
      return LOGOS_OK
  return LOGOS_ERR_METHOD_NOT_FOUND

proc logos_rt_call_start_module(
    ctx: pointer,
    moduleName: cstring,
    out_response: ptr ptr uint8,
    out_response_len: ptr csize_t,
): cint {.exportc, dynlib.} =
  let name = $moduleName
  let res = gRuntime.startModule(name)
  if res.isOk and gRuntime.modules.hasKey(name):
    let response = StartModuleResponse(
      module: name, instance: "", state: gRuntime.modules[name].state
    )
    let bytes = Cbor.encode(response)
    let buf = alloc(bytes.len)
    copyMem(buf, addr bytes[0], bytes.len)
    out_response[] = cast[ptr uint8](buf)
    out_response_len[] = bytes.len.csize_t
    return LOGOS_OK
  return LOGOS_ERR_MODULE

proc logos_rt_call_stop_module(
    ctx: pointer,
    moduleName: cstring,
    out_response: ptr ptr uint8,
    out_response_len: ptr csize_t,
): cint {.exportc, dynlib.} =
  let name = $moduleName
  let res = gRuntime.stopModule(name)
  if res.isOk and gRuntime.modules.hasKey(name):
    let response = StopModuleResponse(
      module: name, instance: Opt.some(""), state: gRuntime.modules[name].state
    )
    let bytes = Cbor.encode(response)
    let buf = alloc(bytes.len)
    copyMem(buf, addr bytes[0], bytes.len)
    out_response[] = cast[ptr uint8](buf)
    out_response_len[] = bytes.len.csize_t
    return LOGOS_OK
  return LOGOS_ERR_MODULE

proc logos_rt_call_get_readiness(
    ctx: pointer,
    moduleName: cstring,
    out_response: ptr ptr uint8,
    out_response_len: ptr csize_t,
): cint {.exportc, dynlib.} =
  let name = $moduleName
  let res = gRuntime.getReadiness(name)
  if res.isOk:
    let (state, reason) = res.get
    let response = GetReadinessResponse(
      module: name, instance: Opt.some(""), state: state, reason: reason
    )
    let bytes = Cbor.encode(response)
    let buf = alloc(bytes.len)
    copyMem(buf, addr bytes[0], bytes.len)
    out_response[] = cast[ptr uint8](buf)
    out_response_len[] = bytes.len.csize_t
    return LOGOS_OK
  else:
    let response = GetReadinessResponse(
      module: name, instance: Opt.some(""), state: msError, reason: Opt.some(res.error)
    )
    let bytes = Cbor.encode(response)
    let buf = alloc(bytes.len)
    copyMem(buf, addr bytes[0], bytes.len)
    out_response[] = cast[ptr uint8](buf)
    out_response_len[] = bytes.len.csize_t
    return LOGOS_ERR_MODULE

# ============================================================================
# Generic dispatch entrypoint (per LOGOS-MODULE-INTERFACE §2.6)
# ============================================================================

proc logos_rt_dispatch(
    ctx: pointer,
    methodName: cstring,
    request_cbor: ptr uint8,
    request_len: csize_t,
    response_cbor: ptr ptr uint8,
    response_len: ptr csize_t,
): cint {.exportc, dynlib.} =
  try:
    let meth = $methodName
    case meth
    of "list_modules":
      return logos_rt_call_list_modules(nil, response_cbor, response_len)
    of "list_routes":
      return logos_rt_call_list_routes(nil, response_cbor, response_len)
    of "revoke_route":
      if request_len > 0 and not request_cbor.isNil:
        var buf = newSeq[byte](request_len)
        copyMem(addr buf[0], request_cbor, request_len)
        let rid = decodeString(buf, "route")
        return logos_rt_call_revoke_route(nil, rid.cstring, response_cbor, response_len)
      else:
        return LOGOS_ERR_INVALID_PARAMS
    of "start_module":
      if request_len > 0 and not request_cbor.isNil:
        var buf = newSeq[byte](request_len)
        copyMem(addr buf[0], request_cbor, request_len)
        let name = decodeString(buf, "module")
        return
          logos_rt_call_start_module(nil, name.cstring, response_cbor, response_len)
      else:
        return LOGOS_ERR_INVALID_PARAMS
    of "stop_module":
      if request_len > 0 and not request_cbor.isNil:
        var buf = newSeq[byte](request_len)
        copyMem(addr buf[0], request_cbor, request_len)
        let name = decodeString(buf, "module")
        return logos_rt_call_stop_module(nil, name.cstring, response_cbor, response_len)
      else:
        return LOGOS_ERR_INVALID_PARAMS
    of "get_readiness":
      if request_len > 0 and not request_cbor.isNil:
        var buf = newSeq[byte](request_len)
        copyMem(addr buf[0], request_cbor, request_len)
        let name = decodeString(buf, "module")
        return
          logos_rt_call_get_readiness(nil, name.cstring, response_cbor, response_len)
      else:
        return LOGOS_ERR_INVALID_PARAMS
    of "logos.schema":
      let buf = alloc(schema.len + 1)
      copyMem(buf, schema.cstring, schema.len + 1)
      response_cbor[] = cast[ptr uint8](buf)
      response_len[] = (schema.len + 1).csize_t
      return LOGOS_OK
    else:
      return LOGOS_ERR_METHOD_NOT_FOUND
  except:
    return LOGOS_ERR_MODULE

# ============================================================================
# Module lifecycle symbols (per LOGOS-MODULE-INTERFACE §2.6)
# ============================================================================

proc logos_module_name(): cstring {.exportc, dynlib.} =
  moduleName.cstring

proc logos_rt_name(): cstring {.exportc, dynlib.} =
  moduleName.cstring

proc logos_rt_schema(): cstring {.exportc, dynlib.} =
  schema.cstring

proc logos_rt_version(): cstring {.exportc, dynlib.} =
  version.cstring

proc logos_rt_init(): cint {.exportc, dynlib.} =
  gRuntime = newRuntime()
  LOGOS_OK

proc logos_rt_destroy(): void {.exportc, dynlib.} =
  gRuntime.shutdown()

proc logos_rt_free(p: pointer) {.exportc, dynlib.} =
  dealloc(p)
