# src/logos_core/rc_cbor.nim
# Canonical deterministic-CBOR layer for the Runtime Control payloads
# (LOGOS-MODULE-RUNTIME §9.3).
#
# One direction per payload type, over the typed model in rt_types.nim:
#   toCbor side  :  <type>Cbor(x): CborValue          (response construction)
#   fromCbor side:  fromCbor<Type>(cv): Result[Type, string]  (request parsing)
#
# The builders emit the exact CDDL field names (snake_case) and honour the
# optional-field semantics: an absent `Opt` field is omitted from the map,
# a present one is written. `CborValue` is the canonical substrate — the
# commitment model digests it structurally, and `encodeCbor` sorts map keys
# bytewise — so the builders need not pre-order fields.

import results
import ./cbor_profile
import ./rt_types
from ./transport import SchemaCommitment
from ./hash_profile import CommitmentModelRevision, HashProfileId, HashSuiteId

# ============================================================================
# Small value builders
# ============================================================================

func cborNull*(): CborValue =
  CborValue(kind: ckNull)

func cborArrayFrom(xs: seq[CborValue]): CborValue =
  CborValue(kind: ckArray, items: xs)

func textArray(xs: seq[string]): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(cborValue(x))
  cborArrayFrom(items)

func bytesArray(xs: seq[seq[byte]]): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(cborValue(x))
  cborArrayFrom(items)

## `logos.schema_commitment` value (INTERFACE §5.1): closed map, three pinned
## literal fields + one 32-byte schema root.
func commitmentCbor(c: SchemaCommitment): CborValue =
  cborMap(
    (cborValue("commitment_model"), cborValue(c.commitmentModel)),
    (cborValue("hash_profile"), cborValue(c.hashProfile)),
    (cborValue("hash_suite"), cborValue(c.hashSuite)),
    (cborValue("schema_root"), cborValue(c.schemaRoot)),
  )

func commitmentArray(xs: seq[SchemaCommitment]): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(commitmentCbor(x))
  cborArrayFrom(items)

## A schema commitment identified only by its 32-byte root (the three pinned
## literal fields are filled with the current revision/profile/suite).
func schemaCommitmentOfRoot*(root: seq[byte]): SchemaCommitment =
  SchemaCommitment(
    commitmentModel: CommitmentModelRevision,
    schemaRoot: root,
    hashProfile: HashProfileId,
    hashSuite: HashSuiteId,
  )

# ============================================================================
# `logos.runtime` supporting-schema value builders
# ============================================================================

## `logos.runtime.module_instance_address`
func moduleInstanceAddressCbor(a: ModuleInstanceAddress): CborValue =
  cborMap(
    (cborValue("runtime_instance_id"), cborValue(a.runtimeInstanceId)),
    (cborValue("module_instance_id"), cborValue(a.moduleInstanceId)),
  )

## `logos.runtime.module_provider_address`
func moduleProviderAddressCbor(a: ModuleProviderAddress): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[]
  if a.runtimeInstanceId.isSome:
    pairs.add((cborValue("runtime_instance_id"), cborValue(a.runtimeInstanceId.get)))
  pairs.add((cborValue("provider"), cborValue(a.provider)))
  cborMap(pairs)

# ============================================================================
# `logos.runtime_control` record builders
# ============================================================================

## `logos.runtime_control.route_access` (32-byte declaration roots). An absent
## list is omitted from the map (permits every declaration of that kind); a
## present empty list is written as an empty array (permits none).
func routeAccessCbor(a: RouteAccess): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[]
  if not a.methodsAbsent:
    pairs.add((cborValue("methods"), bytesArray(a.methods)))
  if not a.publishEventsAbsent:
    pairs.add((cborValue("publish_events"), bytesArray(a.publishEvents)))
  if not a.subscribeEventsAbsent:
    pairs.add((cborValue("subscribe_events"), bytesArray(a.subscribeEvents)))
  cborMap(pairs)

## `logos.runtime_control.invocation_descriptor` (local | remote)
func invocationDescriptorCbor(d: InvocationDescriptor): CborValue =
  if d.kind == "local-transport":
    cborMap(
      (cborValue("kind"), cborValue("local-transport")),
      (cborValue("profile"), cborValue(d.profile.get)),
      (cborValue("path"), cborValue(d.path.get)),
      (cborValue("ticket"), cborValue(d.ticket.get)),
    )
  else:
    cborMap(
      (cborValue("kind"), cborValue("remote-transport")),
      (cborValue("runtime"), cborValue(d.runtime.get)),
      (cborValue("provider"), cborValue(d.provider.get)),
      (cborValue("endpoint"), cborValue("placeholder")),
      (cborValue("ticket"), cborValue(d.ticket.get)),
    )

## `logos.runtime_control.route_failure`
func routeFailureCbor(f: RouteFailure): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[(cborValue("code"), cborValue(f.code))]
  if f.message.isSome:
    pairs.add((cborValue("message"), cborValue(f.message.get)))
  cborMap(pairs)

## `logos.runtime_control.module_record`
func moduleRecordCbor*(r: ModuleRecord): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[(cborValue("module"), cborValue(r.module))]
  if r.provider.isSome:
    pairs.add((cborValue("provider"), moduleProviderAddressCbor(r.provider.get)))
  if r.instance.isSome:
    pairs.add((cborValue("instance"), cborValue(r.instance.get)))
  if r.stateAssignment.isSome:
    pairs.add((cborValue("state_assignment"), cborValue(r.stateAssignment.get)))
  pairs.add((cborValue("state"), cborValue(stateName(r.state))))
  pairs.add((cborValue("mode"), cborValue(modeName(r.mode))))
  if r.primaryContract.isSome:
    pairs.add((cborValue("primary_contract"), commitmentCbor(r.primaryContract.get)))
  if r.implements.len > 0:
    pairs.add((cborValue("implements"), commitmentArray(r.implements)))
  if r.reason.isSome:
    pairs.add((cborValue("reason"), cborValue(r.reason.get)))
  cborMap(pairs)

## `logos.runtime_control.route_record`
func routeRecordCbor*(r: RouteRecord, includeInvocation: bool): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[
    (cborValue("route"), cborValue(r.route)),
    (cborValue("consumer"), moduleInstanceAddressCbor(r.consumer)),
    (cborValue("target_provider"), moduleProviderAddressCbor(r.targetProvider)),
    (cborValue("module"), cborValue(r.module)),
  ]
  if r.instance.isSome:
    pairs.add((cborValue("instance"), cborValue(r.instance.get)))
  if r.expectedContract.isSome:
    pairs.add((cborValue("expected_contract"), commitmentCbor(r.expectedContract.get)))
  pairs.add((cborValue("access"), routeAccessCbor(r.access)))
  pairs.add((cborValue("state"), cborValue(routeStateName(r.state))))
  if includeInvocation and r.invocation.isSome:
    pairs.add((cborValue("invocation"), invocationDescriptorCbor(r.invocation.get)))
  if r.decisionId.isSome:
    pairs.add((cborValue("decision_id"), cborValue(r.decisionId.get)))
  if r.expiresAt.isSome:
    pairs.add((cborValue("expires_at"), cborValue(uint64(r.expiresAt.get))))
  if r.failure.isSome:
    pairs.add((cborValue("failure"), routeFailureCbor(r.failure.get)))
  cborMap(pairs)

func moduleRecordArray*(xs: seq[ModuleRecord]): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(moduleRecordCbor(x))
  cborArrayFrom(items)

func routeRecordArray*(xs: seq[RouteRecord], includeInvocation: bool): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(routeRecordCbor(x, includeInvocation))
  cborArrayFrom(items)

# ============================================================================
# Runtime-address + remote record builders (toCbor side)
# The address types are discriminated by a literal `transport` field; the Nim
# object carries all variant fields and a `kind` selects the populated one.
# ============================================================================

func unixStreamAddressCbor*(a: UnixStreamRuntimeAddress): CborValue =
  var p: seq[(CborValue, CborValue)] = @[
    (cborValue("transport"), cborValue("unix-stream")),
    (cborValue("path"), cborValue(a.path)),
  ]
  if a.profile.isSome:
    p.add((cborValue("profile"), cborValue(a.profile.get)))
  cborMap(p)

func tlsTcpAddressCbor*(a: TlsTcpRuntimeAddress): CborValue =
  var p: seq[(CborValue, CborValue)] = @[
    (cborValue("transport"), cborValue("tls-tcp")),
    (cborValue("host"), cborValue(a.host)),
    (cborValue("port"), cborValue(uint64(a.port))),
  ]
  if a.serverName.isSome:
    p.add((cborValue("server_name"), cborValue(a.serverName.get)))
  if a.profile.isSome:
    p.add((cborValue("profile"), cborValue(a.profile.get)))
  cborMap(p)

func quicAddressCbor*(a: QuicRuntimeAddress): CborValue =
  var p: seq[(CborValue, CborValue)] = @[
    (cborValue("transport"), cborValue("quic")),
    (cborValue("host"), cborValue(a.host)),
    (cborValue("port"), cborValue(uint64(a.port))),
  ]
  if a.serverName.isSome:
    p.add((cborValue("server_name"), cborValue(a.serverName.get)))
  if a.alpn.isSome:
    p.add((cborValue("alpn"), cborValue(a.alpn.get)))
  if a.profile.isSome:
    p.add((cborValue("profile"), cborValue(a.profile.get)))
  cborMap(p)

## `logos.runtime_control.runtime_address` (unix-stream | tls-tcp | quic)
func runtimeAddressCbor*(a: RuntimeAddress): CborValue =
  case a.kind
  of rakUnixStream:
    unixStreamAddressCbor(a.unixStream)
  of rakTlsTcp:
    tlsTcpAddressCbor(a.tlsTcp)
  of rakQuic:
    quicAddressCbor(a.quic)

## `logos.runtime_control.remote_listener_address` (tls-tcp | quic only)
func remoteListenerAddressCbor*(a: RemoteListenerAddress): CborValue =
  case a.kind
  of rakTlsTcp:
    tlsTcpAddressCbor(a.tlsTcp)
  of rakQuic:
    quicAddressCbor(a.quic)
  of rakUnixStream:
    cborNull() ## not a valid remote-listener transport

## `logos.runtime_control.runtime_endpoint`
func runtimeEndpointCbor*(e: RuntimeEndpoint): CborValue =
  var p: seq[(CborValue, CborValue)] =
    @[(cborValue("address"), runtimeAddressCbor(e.address))]
  if e.runtimeInstanceId.isSome:
    p.add((cborValue("runtime_instance_id"), cborValue(e.runtimeInstanceId.get)))
  cborMap(p)

## `logos.runtime_control.remote_provider_target`
func remoteProviderTargetCbor*(t: RemoteProviderTarget): CborValue =
  var p: seq[(CborValue, CborValue)] =
    @[(cborValue("runtime"), runtimeEndpointCbor(t.runtime))]
  if t.provider.isSome:
    p.add((cborValue("provider"), cborValue(t.provider.get)))
  if t.module.isSome:
    p.add((cborValue("module"), cborValue(t.module.get)))
  cborMap(p)

## `logos.runtime_control.remote_runtime_enrollment` (active | revoked)
func remoteRuntimeEnrollmentCbor*(e: RemoteRuntimeEnrollment): CborValue =
  var p: seq[(CborValue, CborValue)] = @[
    (cborValue("runtime_instance_id"), cborValue(e.runtimeInstanceId)),
    (cborValue("profile"), cborValue(e.profile)),
    (cborValue("revision"), cborValue(e.revision)),
    (cborValue("status"), cborValue(e.status)),
  ]
  if e.status == "active":
    if e.trustAnchor.isSome:
      p.add((cborValue("trust_anchor"), cborValue(e.trustAnchor.get)))
    p.add((cborValue("subject_public_keys"), bytesArray(e.subjectPublicKeys)))
  cborMap(p)

## `logos.runtime_control.remote_listener_record`
func remoteListenerRecordCbor*(r: RemoteListenerRecord): CborValue =
  cborMap(
    (cborValue("address"), remoteListenerAddressCbor(r.address)),
    (cborValue("enabled"), cborValue(r.enabled)),
    (cborValue("runtime_control_enabled"), cborValue(r.runtimeControlEnabled)),
  )

func remoteListenerRecordArray(xs: seq[RemoteListenerRecord]): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(remoteListenerRecordCbor(x))
  cborArrayFrom(items)

## `logos.runtime_control.provider_export_record`
func providerExportRecordCbor*(r: ProviderExportRecord): CborValue =
  cborMap(
    (cborValue("listener"), remoteListenerAddressCbor(r.listener)),
    (cborValue("provider"), moduleProviderAddressCbor(r.provider)),
    (cborValue("enabled"), cborValue(r.enabled)),
  )

func providerExportRecordArray(xs: seq[ProviderExportRecord]): CborValue =
  var items: seq[CborValue] = @[]
  for x in xs:
    items.add(providerExportRecordCbor(x))
  cborArrayFrom(items)

# ============================================================================
# Response builders (toCbor side)
# ============================================================================

func listModulesResponseCbor*(r: ListModulesResponse): CborValue =
  cborMap(
    (cborValue("modules"), moduleRecordArray(r.modules)),
    (cborValue("partial"), cborValue(r.partial)),
  )

func listRoutesResponseCbor*(r: ListRoutesResponse): CborValue =
  cborMap(
    (cborValue("routes"), routeRecordArray(r.routes, false)),
    (cborValue("partial"), cborValue(r.partial)),
  )

func establishRouteResponseCbor*(r: EstablishRouteResponse): CborValue =
  cborMap(
    (cborValue("routes"), routeRecordArray(r.routes, true)),
    (cborValue("partial"), cborValue(r.partial)),
  )

func closeRouteResponseCbor*(r: CloseRouteResponse): CborValue =
  cborMap(
    (cborValue("route"), cborValue(r.route)),
    (cborValue("state"), cborValue(routeStateName(r.state))),
  )

func startModuleResponseCbor*(r: StartModuleResponse): CborValue =
  cborMap(
    (cborValue("module"), cborValue(r.module)),
    (cborValue("instance"), cborValue(r.instance)),
    (cborValue("state"), cborValue(stateName(r.state))),
  )

func stopModuleResponseCbor*(r: StopModuleResponse): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[(cborValue("module"), cborValue(r.module))]
  if r.instance.isSome:
    pairs.add((cborValue("instance"), cborValue(r.instance.get)))
  pairs.add((cborValue("state"), cborValue(stateName(r.state))))
  cborMap(pairs)

func getReadinessResponseCbor*(r: GetReadinessResponse): CborValue =
  var pairs: seq[(CborValue, CborValue)] = @[(cborValue("module"), cborValue(r.module))]
  if r.instance.isSome:
    pairs.add((cborValue("instance"), cborValue(r.instance.get)))
  pairs.add((cborValue("state"), cborValue(stateName(r.state))))
  if r.reason.isSome:
    pairs.add((cborValue("reason"), cborValue(r.reason.get)))
  cborMap(pairs)

func renewRouteResponseCbor*(r: RenewRouteResponse): CborValue =
  cborMap((cborValue("route"), routeRecordCbor(r.route, true)))

func listRemoteListenersResponseCbor*(r: ListRemoteListenersResponse): CborValue =
  cborMap(
    (cborValue("listeners"), remoteListenerRecordArray(r.listeners)),
    (cborValue("partial"), cborValue(r.partial)),
  )

func setRemoteListenerRequestCbor*(r: SetRemoteListenerRequest): CborValue =
  cborMap((cborValue("listener"), remoteListenerRecordCbor(r.listener)))

func setRemoteListenerResponseCbor*(r: SetRemoteListenerResponse): CborValue =
  cborMap((cborValue("listener"), remoteListenerRecordCbor(r.listener)))

func listProviderExportsResponseCbor*(r: ListProviderExportsResponse): CborValue =
  cborMap(
    (cborValue("exports"), providerExportRecordArray(r.exports)),
    (cborValue("partial"), cborValue(r.partial)),
  )

## CDDL key is `export` (the Nim field is `exportRecord`).
func setProviderExportRequestCbor*(r: SetProviderExportRequest): CborValue =
  cborMap((cborValue("export"), providerExportRecordCbor(r.exportRecord)))

func setProviderExportResponseCbor*(r: SetProviderExportResponse): CborValue =
  cborMap((cborValue("export"), providerExportRecordCbor(r.exportRecord)))

# ============================================================================
# Event builders (toCbor side)
# ============================================================================

func moduleStateChangedEventCbor*(e: ModuleStateChangedEvent): CborValue =
  var p: seq[(CborValue, CborValue)] = @[
    (cborValue("module"), cborValue(e.module)),
    (cborValue("old_state"), cborValue(stateName(e.oldState))),
    (cborValue("new_state"), cborValue(stateName(e.newState))),
  ]
  if e.instance.isSome:
    p.add((cborValue("instance"), cborValue(e.instance.get)))
  if e.reason.isSome:
    p.add((cborValue("reason"), cborValue(e.reason.get)))
  cborMap(p)

func routeStateChangedEventCbor*(e: RouteStateChangedEvent): CborValue =
  var p: seq[(CborValue, CborValue)] = @[
    (cborValue("route"), cborValue(e.route)),
    (cborValue("old_state"), cborValue(routeStateName(e.oldState))),
    (cborValue("new_state"), cborValue(routeStateName(e.newState))),
  ]
  if e.module.isSome:
    p.add((cborValue("module"), cborValue(e.module.get)))
  if e.provider.isSome:
    p.add((cborValue("provider"), moduleProviderAddressCbor(e.provider.get)))
  if e.reason.isSome:
    p.add((cborValue("reason"), cborValue(e.reason.get)))
  cborMap(p)

# ============================================================================
# Request parsers (fromCbor side)
# ============================================================================

func textField(cv: CborValue, key: string): Opt[string] =
  let v = cv.mapGet(key)
  if v.kind == ckText:
    Opt.some(v.s)
  else:
    Opt.none(string)

## Parse a present `route_access` list of 32-byte declaration roots. Returns
## `some(items)` when the key is present (even if the array is empty) and
## `none` when the key is absent (permits every declaration of that kind).
func accessListField(cv: CborValue, key: string): Result[Opt[seq[seq[byte]]], string] =
  let v = cv.mapGet(key)
  if v.kind != ckArray:
    return ok(Opt.none(seq[seq[byte]]))
  var items: seq[seq[byte]] = @[]
  for it in v.items:
    if it.kind != ckBytes or it.by.len != 32:
      return err("bad route_access " & key & " entry")
    items.add(it.by)
  ok(Opt.some(items))

## Parse a `route_access` scope (RUNTIME §9.3). Absent keys permit every
## declaration of that kind; present keys (even empty) restrict to the list.
proc routeAccessFromCbor(cv: CborValue): Result[RouteAccess, string] =
  var a = RouteAccess(
    methodsAbsent: true, publishEventsAbsent: true, subscribeEventsAbsent: true
  )
  let m = ?accessListField(cv, "methods")
  if m.isSome:
    a.methodsAbsent = false
    a.methods = m.get
  let pe = ?accessListField(cv, "publish_events")
  if pe.isSome:
    a.publishEventsAbsent = false
    a.publishEvents = pe.get
  let se = ?accessListField(cv, "subscribe_events")
  if se.isSome:
    a.subscribeEventsAbsent = false
    a.subscribeEvents = se.get
  ok(a)

func fromCborCloseRouteRequest*(cv: CborValue): Result[CloseRouteRequest, string] =
  let route = textField(cv, "route")
  if route.isNone:
    return err("missing route")
  var r = CloseRouteRequest(route: route.get)
  let reason = textField(cv, "reason")
  if reason.isSome:
    r.reason = reason
  ok(r)

func fromCborStartModuleRequest*(cv: CborValue): Result[StartModuleRequest, string] =
  let module = textField(cv, "module")
  if module.isNone:
    return err("missing module")
  var r = StartModuleRequest(module: module.get)
  let instance = textField(cv, "instance")
  if instance.isSome:
    r.instance = instance
  ok(r)

func fromCborStopModuleRequest*(cv: CborValue): Result[StopModuleRequest, string] =
  let module = textField(cv, "module")
  if module.isNone:
    return err("missing module")
  var r = StopModuleRequest(module: module.get)
  let instance = textField(cv, "instance")
  if instance.isSome:
    r.instance = instance
  ok(r)

func fromCborGetReadinessRequest*(cv: CborValue): Result[GetReadinessRequest, string] =
  let module = textField(cv, "module")
  if module.isNone:
    return err("missing module")
  var r = GetReadinessRequest(module: module.get)
  let instance = textField(cv, "instance")
  if instance.isSome:
    r.instance = instance
  ok(r)

proc fromCborEstablishRouteRequest*(
    cv: CborValue
): Result[EstablishRouteRequest, string] =
  let rk = textField(cv, "request_key")
  if rk.isNone or rk.get.len < 1 or rk.get.len > 128:
    return err("bad request_key")
  let contract = cv.mapGet("contract")
  if contract.kind != ckMap:
    return err("missing contract")
  let cr = contract.mapGet("schema_root")
  if cr.kind != ckBytes or cr.by.len != 32:
    return err("bad contract schema_root")
  let card = textField(cv, "cardinality")
  if card.isNone or (card.get != "single" and card.get != "all-runtime-visible"):
    return err("bad cardinality")
  # Optional provider (absent = the provider matching the contract).
  var provider = Opt.none(ModuleProviderAddress)
  let pv = cv.mapGet("provider")
  if pv.kind == ckMap:
    let ppid = pv.mapGet("provider")
    if ppid.kind == ckText:
      provider = Opt.some(
        ModuleProviderAddress(
          runtimeInstanceId: Opt.none(RuntimeInstanceId), provider: ppid.s
        )
      )
  let access = ?routeAccessFromCbor(cv.mapGet("access"))
  ok(
    EstablishRouteRequest(
      requestKey: rk.get,
      contract: schemaCommitmentOfRoot(cr.by),
      cardinality: card.get,
      provider: provider,
      access: access,
    )
  )

# ============================================================================
# Address / record parsers (fromCbor side) — shared by the remote requests
# ============================================================================

func uintField(cv: CborValue, key: string): Opt[uint64] =
  let v = cv.mapGet(key)
  if v.kind == ckUint:
    Opt.some(v.u)
  else:
    Opt.none(uint64)

func boolField(cv: CborValue, key: string): Opt[bool] =
  let v = cv.mapGet(key)
  if v.kind == ckBool:
    Opt.some(v.b)
  else:
    Opt.none(bool)

func moduleProviderAddressFromCbor*(
    cv: CborValue
): Result[ModuleProviderAddress, string] =
  let p = textField(cv, "provider")
  if p.isNone:
    return err("missing provider")
  var a = ModuleProviderAddress(provider: p.get)
  let rid = textField(cv, "runtime_instance_id")
  if rid.isSome:
    a.runtimeInstanceId = rid
  ok(a)

func tlsTcpAddressFromCbor(cv: CborValue): Result[TlsTcpRuntimeAddress, string] =
  let host = textField(cv, "host")
  if host.isNone:
    return err("missing host")
  let port = uintField(cv, "port")
  if port.isNone:
    return err("missing port")
  var a = TlsTcpRuntimeAddress(host: host.get, port: uint16(port.get))
  let sn = textField(cv, "server_name")
  if sn.isSome:
    a.serverName = sn
  let prof = textField(cv, "profile")
  if prof.isSome:
    a.profile = prof
  ok(a)

func quicAddressFromCbor(cv: CborValue): Result[QuicRuntimeAddress, string] =
  let host = textField(cv, "host")
  if host.isNone:
    return err("missing host")
  let port = uintField(cv, "port")
  if port.isNone:
    return err("missing port")
  var a = QuicRuntimeAddress(host: host.get, port: uint16(port.get))
  let sn = textField(cv, "server_name")
  if sn.isSome:
    a.serverName = sn
  let alpn = textField(cv, "alpn")
  if alpn.isSome:
    a.alpn = alpn
  let prof = textField(cv, "profile")
  if prof.isSome:
    a.profile = prof
  ok(a)

## `logos.runtime_control.runtime_address` (discriminated by `transport`)
proc runtimeAddressFromCbor*(cv: CborValue): Result[RuntimeAddress, string] =
  let t = textField(cv, "transport")
  if t.isNone:
    return err("missing transport")
  case t.get
  of "unix-stream":
    let path = textField(cv, "path")
    if path.isNone:
      return err("missing path")
    var a = UnixStreamRuntimeAddress(path: path.get)
    let prof = textField(cv, "profile")
    if prof.isSome:
      a.profile = prof
    ok(RuntimeAddress(kind: rakUnixStream, unixStream: a))
  of "tls-tcp":
    let a = ?tlsTcpAddressFromCbor(cv)
    ok(RuntimeAddress(kind: rakTlsTcp, tlsTcp: a))
  of "quic":
    let a = ?quicAddressFromCbor(cv)
    ok(RuntimeAddress(kind: rakQuic, quic: a))
  else:
    err("unknown transport")

## `logos.runtime_control.remote_listener_address` (tls-tcp | quic only)
proc remoteListenerAddressFromCbor*(
    cv: CborValue
): Result[RemoteListenerAddress, string] =
  let t = textField(cv, "transport")
  if t.isNone:
    return err("missing transport")
  case t.get
  of "tls-tcp":
    let a = ?tlsTcpAddressFromCbor(cv)
    ok(RemoteListenerAddress(kind: rakTlsTcp, tlsTcp: a))
  of "quic":
    let a = ?quicAddressFromCbor(cv)
    ok(RemoteListenerAddress(kind: rakQuic, quic: a))
  else:
    err("invalid remote-listener transport")

proc remoteListenerRecordFromCbor*(
    cv: CborValue
): Result[RemoteListenerRecord, string] =
  let address = remoteListenerAddressFromCbor(cv.mapGet("address"))
  if address.isErr:
    return err(address.error)
  let enabled = boolField(cv, "enabled")
  if enabled.isNone:
    return err("missing enabled")
  let rce = boolField(cv, "runtime_control_enabled")
  if rce.isNone:
    return err("missing runtime_control_enabled")
  ok(
    RemoteListenerRecord(
      address: address.get, enabled: enabled.get, runtimeControlEnabled: rce.get
    )
  )

proc providerExportRecordFromCbor*(
    cv: CborValue
): Result[ProviderExportRecord, string] =
  let listener = remoteListenerAddressFromCbor(cv.mapGet("listener"))
  if listener.isErr:
    return err(listener.error)
  let provider = moduleProviderAddressFromCbor(cv.mapGet("provider"))
  if provider.isErr:
    return err(provider.error)
  let enabled = boolField(cv, "enabled")
  if enabled.isNone:
    return err("missing enabled")
  ok(
    ProviderExportRecord(
      listener: listener.get, provider: provider.get, enabled: enabled.get
    )
  )

# ============================================================================
# Remote / renew request parsers (fromCbor side)
# ============================================================================

func fromCborListRoutesRequest*(cv: CborValue): Result[ListRoutesRequest, string] =
  ## A null/absent request means no fields present (all optional fields absent).
  var r = ListRoutesRequest()
  let m = textField(cv, "module")
  if m.isSome:
    r.module = m
  let p = moduleProviderAddressFromCbor(cv.mapGet("provider"))
  if p.isOk:
    r.provider = Opt.some(p.get)
  ok(r)

proc fromCborRenewRouteRequest*(cv: CborValue): Result[RenewRouteRequest, string] =
  let rk = textField(cv, "request_key")
  if rk.isNone or rk.get.len < 1 or rk.get.len > 128:
    return err("bad request_key")
  let route = textField(cv, "route")
  if route.isNone:
    return err("missing route")
  ok(RenewRouteRequest(requestKey: rk.get, route: route.get))

proc fromCborSetRemoteListenerRequest*(
    cv: CborValue
): Result[SetRemoteListenerRequest, string] =
  let l = remoteListenerRecordFromCbor(cv.mapGet("listener"))
  if l.isErr:
    return err(l.error)
  ok(SetRemoteListenerRequest(listener: l.get))

proc fromCborListProviderExportsRequest*(
    cv: CborValue
): Result[ListProviderExportsRequest, string] =
  var r = ListProviderExportsRequest()
  let l = remoteListenerAddressFromCbor(cv.mapGet("listener"))
  if l.isOk:
    r.listener = Opt.some(l.get)
  let p = moduleProviderAddressFromCbor(cv.mapGet("provider"))
  if p.isOk:
    r.provider = Opt.some(p.get)
  ok(r)

proc fromCborSetProviderExportRequest*(
    cv: CborValue
): Result[SetProviderExportRequest, string] =
  let e = providerExportRecordFromCbor(cv.mapGet("export"))
  if e.isErr:
    return err(e.error)
  ok(SetProviderExportRequest(exportRecord: e.get))
