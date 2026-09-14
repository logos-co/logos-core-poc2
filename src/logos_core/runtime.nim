# src/logos_core/runtime.nim
# The Runtime: module lifecycle + the Runtime Control engine
# (LOGOS-MODULE-RUNTIME §9). The conformant local transport is the
# unix-stream host (§9.3 / TRANSPORT §8); the legacy plain-TCP path is kept
# for the development CLI/TUI.

{.push gcsafe, raises: [].}

import
  ./[modules, rt_types, shared_modules, tcp_modules, tcp_host, tcp_protocols],
  ./[unix_transport, route_tickets, cbor_profile],
  results,
  std/[tables, os, net, sequtils, strutils, sets]

from ./abi_types import
  LogosResult, LogosRuntimeControlBinding, LogosRuntimeControlVtable,
  LogosModuleContext, LogosPublishFn, LogosEventHandler, LogosSubscriptionId,
  LogosRouteHandle

type
  ## One runtime-known module instance (POC: one instance per module name).
  ModuleInfo* = object
    m*: ref Module
    state*: ModuleState
    instanceId*: string
    mode*: ModuleMode
    provider*: Opt[ModuleProviderAddress]
    remote*: Opt[RemoteProviderTarget]
    stateAssignment*: Opt[ModuleStateAssignmentId]
    primaryContract*: Opt[SchemaCommitment]
    implements*: seq[SchemaCommitment]
    reason*: Opt[Reason]

  ## One route (keyed by route id). The record carries the authoritative
  ## state; the invocation material (ticket) is revoked on close.
  RouteInfo* = object
    record*: RouteRecord
    ticket*: seq[byte] ## the raw route ticket (for revocation on close)

  ## The Runtime instance: owns the module table, the route table, the
  ## route-ticket store, the local unix-stream host, and the state-event log.
  Runtime* = object
    runtimeInstanceId*: RuntimeInstanceId
    modules*: Table[string, ModuleInfo]
    subscribers*: seq[Socket]
    tcpHost*: ref TcpHost
    routes*: Table[RouteId, RouteInfo]
    ticketStore*: TicketStore
    unixHost*: ref UnixHost
    unixHostModule*: string
    moduleEvents*: seq[ModuleStateChangedEvent]
    routeEvents*: seq[RouteStateChangedEvent]
    ## request_key idempotency, consumer-scoped (§9.1): keyed by
    ## "<consumer.instanceId>/<request_key>" -> the established route ids.
    requestKeys*: Table[string, seq[RouteId]]
    ## N5: the contract root bound to each request_key, so a repeat with a
    ## different contract (different-fields check, §9.3) is rejected.
    requestKeyContracts: Table[string, seq[byte]]
    ## N1: the authority policy (explicit allow/deny, not a stub allow).
    authority: AuthorityPolicy
    ## N4: consumers whose Runtime Control binding was invalidated by a stop
    ## ("<runtimeInstanceId>/<moduleInstanceId>"); later RC calls are rejected.
    invalidatedConsumers: HashSet[string]
    ## N1: monotonic decision counter (unique decision ids per invocation).
    decisionCounter: int

# ============================================================================
# Stub runtime-control binding (Phase 2)
# The real runtime-control vtable is wired in rt.nim; the stub is kept so the
# legacy load path still builds. Raw memory (process-lifetime).
# ============================================================================

proc stubRcNotReady(): LogosResult {.gcsafe, raises: [].} =
  LogosResult(code: LOGOS_ERR_NOT_READY, message: "runtime control not ready".cstring)

proc stubRcCall(
    b: ptr LogosRuntimeControlBinding,
    m: cstring,
    p: ptr uint8,
    l: csize_t,
    o: ptr ptr uint8,
    ol: ptr csize_t,
): LogosResult {.gcsafe, raises: [].} =
  stubRcNotReady()

proc stubRcRelease(
    b: ptr LogosRuntimeControlBinding, p: ptr uint8, l: csize_t
) {.gcsafe, raises: [].} =
  discard b
  discard p
  discard l

proc stubRcSubscribe(
    b: ptr LogosRuntimeControlBinding,
    e: cstring,
    h: LogosEventHandler,
    u: pointer,
    o: ptr LogosSubscriptionId,
): LogosResult {.gcsafe, raises: [].} =
  stubRcNotReady()

proc stubRcUnsubscribe(
    b: ptr LogosRuntimeControlBinding, s: LogosSubscriptionId
): LogosResult {.gcsafe, raises: [].} =
  stubRcNotReady()

proc stubRcMaterializeRoute(
    b: ptr LogosRuntimeControlBinding, r: cstring, e: ptr uint8, o: ptr LogosRouteHandle
): LogosResult {.gcsafe, raises: [].} =
  stubRcNotReady()

## Create a Runtime Control binding whose `state` field carries a
## pointer to the owning Runtime. The logos_runtime_control module reads this
## pointer in logos_logos_runtime_control_init to locate the Runtime it controls.
proc makeStubRcBinding*(
    runtimePtr: ptr Runtime
): ptr LogosRuntimeControlBinding {.gcsafe, raises: [].} =
  let vtMem =
    cast[ptr LogosRuntimeControlVtable](alloc0(sizeof(LogosRuntimeControlVtable)))
  vtMem[] = LogosRuntimeControlVtable(
    abiVersion: 1,
    structSize: sizeof(LogosRuntimeControlVtable).csize_t,
    call: stubRcCall,
    releaseResponse: stubRcRelease,
    subscribe: stubRcSubscribe,
    unsubscribe: stubRcUnsubscribe,
    materializeRoute: stubRcMaterializeRoute,
  )
  let stateMem = cast[pointer](alloc0(sizeof(ptr Runtime)))
  cast[ptr ptr Runtime](stateMem)[] = runtimePtr
  let bindingMem =
    cast[ptr LogosRuntimeControlBinding](alloc0(sizeof(LogosRuntimeControlBinding)))
  bindingMem[] = LogosRuntimeControlBinding(vtable: vtMem, state: stateMem)
  bindingMem

## Stub publish callback: POC modules declare events but the runtime
## does not yet deliver them (Phase 5). Satisfies the ABI requirement
## that a non-null publish callback be supplied when the call surface
## declares events.
proc stubPublish(
    userData: pointer, eventName: cstring, cborData: ptr uint8, cborDataLen: csize_t
) {.cdecl, gcsafe, raises: [].} =
  discard userData
  discard eventName
  discard cborData
  discard cborDataLen

## Closure helpers bridging the high-level Module closures to the new ABI.
proc doInitModule(
    m: var Module, shared: ptr SharedModule, rcBinding: ptr LogosRuntimeControlBinding
): cint =
  let c = shared[].initInstance(rcBinding, stubPublish, nil, "", @[])
  if c.isOk:
    m.ctx = c.get
    0
  else:
    1

proc doDestroyModule(m: var Module, shared: ptr SharedModule) =
  if m.ctx != nil:
    discard shared[].destroyInstance(m.ctx)
    m.ctx = nil

proc doDispatchModule(
    m: Module, shared: ptr SharedModule, meth: string, params: openArray[byte]
): Result[seq[byte], string] =
  if m.ctx == nil:
    err("module not initialized")
  else:
    shared[].dispatch(m.ctx, meth, params)

proc doFreeModule(m: Module, shared: ptr SharedModule, p: pointer) =
  if p != nil and m.ctx != nil:
    shared[].freeFn(m.ctx, p)

proc newRuntime*(instanceId: RuntimeInstanceId = "local-runtime"): Runtime =
  Runtime(
    runtimeInstanceId: instanceId,
    modules: initTable[string, ModuleInfo](),
    subscribers: @[],
    tcpHost: nil,
    routes: initTable[RouteId, RouteInfo](),
    ticketStore: newTicketStore(),
    unixHost: nil,
    unixHostModule: "",
    moduleEvents: @[],
    routeEvents: @[],
    requestKeys: initTable[string, seq[RouteId]](),
    requestKeyContracts: initTable[string, seq[byte]](),
    authority: AuthorityPolicy(allowAuthenticated: true),
    invalidatedConsumers: initHashSet[string](),
    decisionCounter: 0,
  )

proc registerModule*(runtime: var Runtime, name: string, info: sink ModuleInfo) =
  runtime.modules[name] = info

## Record a module-state transition (ordered emission, §9.1). Mutates the
## table entry in place and appends the event in completion order.
proc emitModuleEvent*(
    runtime: var Runtime, name: string, newState: ModuleState, reason: Opt[Reason]
) =
  runtime.modules.withValue(name, info):
    runtime.moduleEvents.add(
      ModuleStateChangedEvent(
        module: name,
        instance:
          if info.instanceId.len > 0:
            Opt.some(info.instanceId)
          else:
            Opt.none(ModuleInstanceId),
        oldState: info.state,
        newState: newState,
        reason: reason,
      )
    )
    info.state = newState
    info.reason = reason

## Record a route-state transition (ordered emission, §9.1). Mutates the
## table entry in place and appends the event in completion order.
proc emitRouteEvent*(
    runtime: var Runtime,
    routeId: RouteId,
    newState: RouteState,
    module: ModuleName,
    provider: ModuleProviderAddress,
    reason: Opt[Reason],
) =
  var oldState = rsReady
  runtime.routes.withValue(routeId, ri):
    oldState = ri.record.state
    ri.record.state = newState
  runtime.routeEvents.add(
    RouteStateChangedEvent(
      route: routeId,
      oldState: oldState,
      newState: newState,
      module: Opt.some(module),
      provider: Opt.some(provider),
      reason: reason,
    )
  )

proc shutdown*(runtime: var Runtime) =
  if runtime.tcpHost != nil:
    stopHost(runtime.tcpHost)
    runtime.tcpHost = nil
  if runtime.unixHost != nil:
    stopUnixHost(runtime.unixHost)
    runtime.unixHost = nil
    runtime.unixHostModule = ""
  for name in runtime.modules.keys.toSeq:
    try:
      let info = runtime.modules[name]
      if not info.m.destroyFn.isNil:
        info.m.destroyFn()
    except:
      discard
  runtime.modules.clear()
  runtime.routes.clear()

{.pop.}

proc load*(
    runtime: var Runtime, path, expectedName: string, isProvider: bool
): Result[(string, string), string] =
  ## Load a module. TCP targets keep the legacy transport path; native
  ## modules use known-name resolution and full call-surface validation
  ## (RUNTIME §3.6).
  if isTcpTarget(path):
    let tcp = ?TcpModule.init(path)
    let res = (tcp.moduleName, tcp.version)
    let module = Module(
      name: tcp.moduleName,
      host: path,
      schema: tcp.schema,
      version: tcp.version,
      initFn: proc(): cint =
        0,
      dispatchFn: proc(
          meth: string, params: openArray[byte]
      ): Result[seq[byte], string] =
        tcp.dispatch(meth, params),
      destroyFn: proc() =
        tcp.destroy(),
    )
    let moduleRef = (ref Module)()
    moduleRef[] = module
    runtime.registerModule(
      moduleRef[].name,
      ModuleInfo(
        m: moduleRef,
        state: msLoaded,
        instanceId: moduleRef[].name,
        mode: mmLocalTransport,
      ),
    )
    ok(res)
  else:
    var loaded = init(path, expectedName, isProvider)
    if loaded.isErr:
      return err(loaded.error)
    let shared = (ref SharedModule)()
    shared[] = move(loaded.get)
    let rcBinding = makeStubRcBinding(addr runtime)
    let schemaText =
      if shared.surface.primary.isSome: shared.surface.primary.get.document else: ""
    var module = Module(
      name: shared.name,
      host: path,
      schema: schemaText,
      version: "",
      shared: cast[ptr SharedModule](shared),
      ctx: nil,
      rcBinding: rcBinding,
    )
    let moduleRef = (ref Module)()
    moduleRef[] = move(module)
    moduleRef[].initFn = proc(): cint =
      doInitModule(moduleRef[], cast[ptr SharedModule](shared), rcBinding)
    moduleRef[].destroyFn = proc() =
      doDestroyModule(moduleRef[], cast[ptr SharedModule](shared))
    moduleRef[].dispatchFn = proc(
        meth: string, params: openArray[byte]
    ): Result[seq[byte], string] =
      doDispatchModule(moduleRef[], cast[ptr SharedModule](shared), meth, params)
    moduleRef[].freeFn = proc(p: pointer) =
      doFreeModule(moduleRef[], cast[ptr SharedModule](shared), p)
    # Derive the primary contract commitment from the provider's schema.
    var primary: Opt[SchemaCommitment] = Opt.none(SchemaCommitment)
    if schemaText.len > 0:
      let sc = schemaCommitmentOf(schemaText)
      if sc.isOk:
        primary = Opt.some(sc.get)
    runtime.registerModule(
      moduleRef[].name,
      ModuleInfo(
        m: moduleRef,
        state: msLoaded,
        instanceId: moduleRef[].name,
        mode: mmDirect,
        primaryContract: primary,
      ),
    )
    ok((shared.name, ""))

{.push gcsafe, raises: [].}

proc unload*(runtime: var Runtime, name: string): Result[void, string] =
  runtime.modules.withValue(name, module):
    if not module[].m.destroyFn.isNil:
      module[].m.destroyFn()
    runtime.modules.del name
    return ok()
  do:
    return err("Plugin not loaded: " & name)

proc listPlugins*(runtime: Runtime): seq[string] =
  runtime.modules.keys.toSeq

proc pluginSchema*(runtime: Runtime, name: string): Result[string, string] =
  try:
    ok(runtime.modules[name].m.schema)
  except:
    err("Plugin not loaded: " & name)

{.pop.}

proc dispatchPlugin*(
    runtime: var Runtime, name, methodName: string, params: seq[byte]
): Result[seq[byte], string] =
  ## Not gcsafe: drives the new-ABI path (lazy instance init + dispatch).
  try:
    let m = runtime.modules[name].m
    if m.shared != nil and m.ctx == nil:
      let code = m.initFn()
      if code != 0:
        return err("module initialization failed: code " & $code)
    m.dispatchFn(methodName, params)
  except KeyError:
    err("Plugin not loaded: " & name)

{.push gcsafe, raises: [].}

proc moduleNameFromPath*(path: string): string =
  let parts = path.split('/')
  let base = parts[parts.len - 1]
  let stem = base.split('.')[0]
  if stem.startsWith("lib") and stem.len > 3:
    stem[3 ..^ 1]
  else:
    stem

proc startTcpHost*(runtime: var Runtime, port: net.Port): Result[net.Port, string] =
  if runtime.tcpHost != nil and runtime.tcpHost.running:
    return err("TCP host already running")
  let rt = addr runtime
  let hostRes = startHost(
    proc(path: string): Result[(string, string), string] =
      err("native module loading over TCP is not available in the POC"),
    proc(name: string): Result[void, string] =
      rt[].unload(name),
    proc(): seq[string] =
      rt[].listPlugins(),
    proc(
        plugin: string, methodName: string, params: seq[byte]
    ): Result[seq[byte], string] =
      err("native dispatch over TCP is not available in the POC"),
    port,
  )
  runtime.tcpHost = hostRes.valueOr:
    return err(error)
  ok(runtime.tcpHost.port)

proc stopTcpHost*(runtime: var Runtime): Result[void, string] =
  if runtime.tcpHost == nil:
    return ok()
  stopHost(runtime.tcpHost)
  runtime.tcpHost = nil
  ok()

# ============================================================================
# Local unix-stream host (TRANSPORT §8) — the conformant provider endpoint.
# One host per Runtime (POC: the single provider module being served).
# ============================================================================

{.pop.}

proc startUnixHost*(
    runtime: var Runtime, baseDir, module: string
): Result[string, string] =
  ## Start the provider-side unix-stream host for `module`. The dispatch
  ## callback bridges to the Runtime's dispatch (the provider is a local
  ## module instance). Returns the socket path (the invocation endpoint).
  if runtime.unixHost != nil:
    return err("unix host already running for " & runtime.unixHostModule)
  let schema = ?pluginSchema(runtime, module)
  let rt = addr runtime
  let dispatch: UnixHostDispatch = proc(
      methodName: string, params: cbor_profile.CborValue
  ): Result[cbor_profile.CborValue, string] =
    let raw = cbor_profile.encodeCbor(params)
    let res = rt[].dispatchPlugin(module, methodName, raw)
    if res.isOk:
      try:
        let v = cbor_profile.decodeCbor(res.get)
        ok(v)
      except cbor_profile.CborError:
        # a specific-type catch: a base-class catch does not reliably catch
        # ref exceptions on every supported Nim version (K10)
        err("failed to decode provider response")
    else:
      err(res.error)
  let host = ?newUnixHost(baseDir, module, schema, runtime.ticketStore, dispatch)
  runtime.unixHost = host
  runtime.unixHostModule = module
  ok(host.socketPath)

proc stopUnixHostForRuntime*(runtime: var Runtime) =
  if runtime.unixHost != nil:
    stopUnixHost(runtime.unixHost)
    runtime.unixHost = nil
    runtime.unixHostModule = ""

proc serveUnixHost*(runtime: var Runtime) =
  ## Run the provider-side unix-stream serve loop (blocking, TRANSPORT §8).
  ## The conformant local-transport path: one session at a time (POC).
  if runtime.unixHost == nil:
    raise newException(Exception, "no unix host running")
  serveLoop(runtime.unixHost)

# ============================================================================
# Runtime Control engine (§9.3) — not gcsafe: drives the new-ABI dispatch
# (lazy instance init + GC) and the route-ticket store.
# ============================================================================

## Build a `module_record` observation from a ModuleInfo.
func moduleRecordOf(info: ModuleInfo): ModuleRecord =
  ModuleRecord(
    module: info.m.name,
    provider: info.provider,
    remote: info.remote,
    instance:
      if info.instanceId.len > 0:
        Opt.some(info.instanceId)
      else:
        Opt.none(ModuleInstanceId),
    stateAssignment: info.stateAssignment,
    state: info.state,
    mode: info.mode,
    primaryContract: info.primaryContract,
    implements: info.implements,
    reason: info.reason,
  )

## Best-effort ASCII decode of a "root" that actually carries a name (POC:
## the route-access "32-byte roots" carry the bare method/event names).
func decodeAsciiString(b: seq[byte]): string =
  result = ""
  for c in b:
    if c >= 32 and c < 127:
      result.add(char(c))

## Build the ticket access from a route access (introspection always allowed).
## The absent-vs-empty semantics (RUNTIME §9.3) are preserved: an absent list
## permits every declaration of that kind; a present empty list permits none.
func ticketAccessOf(access: RouteAccess): TicketAccess =
  TicketAccess(
    methods: access.methods.mapIt(it.decodeAsciiString()),
    events: access.publishEvents.mapIt(it.decodeAsciiString()),
    allowSchema: true,
    methodsAbsent: access.methodsAbsent,
    eventsAbsent: access.publishEventsAbsent,
  )

# ============================================================================
# N1: consumer authentication + authority evaluation
# ============================================================================

## The consumer key for the invalidated-binding set ("<rt>/<instance>").
func consumerKey(consumer: ModuleInstanceAddress): string =
  consumer.runtimeInstanceId & "/" & consumer.moduleInstanceId

## N1: consumer authentication (RUNTIME §9). A consumer is authenticated if it
## is a module instance this runtime owns (an admitted module whose instanceId
## matches the consumer's moduleInstanceId, with a matching runtimeInstanceId),
## or the runtime's own bootstrap identity (the host, for the shared RC module).
## The consumer reference does not itself grant authority — it is only the
## identity the authority policy then evaluates.
proc authenticateConsumer*(
    runtime: Runtime, consumer: ModuleInstanceAddress
): Result[void, string] =
  if consumer.runtimeInstanceId != runtime.runtimeInstanceId:
    return err("consumer is not owned by this runtime")
  for name in runtime.modules.keys:
    let info = runtime.modules[name]
    if info.instanceId == consumer.moduleInstanceId:
      return ok()
  # The runtime's own bootstrap identity (the host; POC shared RC module).
  if consumer.moduleInstanceId == runtime.runtimeInstanceId:
    return ok()
  err("consumer is not an admitted module instance: " & consumer.moduleInstanceId)

## N1: authority evaluation (RUNTIME §9). Applies the policy to an
## authenticated consumer and produces an explicit allow/deny decision — not a
## stub allow. Returns the allow decision, or an error on authentication
## failure or policy denial (the caller MUST reject the invocation).
proc requireAuthority*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, methodName: string
): Result[AuthorityDecision, string] =
  ?authenticateConsumer(runtime, consumer)
  runtime.decisionCounter += 1
  let decisionId = "decision-" & $runtime.decisionCounter
  if runtime.authority.allowAuthenticated:
    return ok(
      AuthorityDecision(
        allowed: true,
        decisionId: decisionId,
        reason: "allow " & methodName & " for authenticated consumer",
      )
    )
  err("authority denied " & methodName & " for " & consumer.moduleInstanceId)

## The RC invocation gate: N4 rejects any call through an invalidated RC
## binding, then N1 authenticates + authorizes. Every RC method MUST call this
## before applying a state mutation or returning observation.
proc checkRcInvocation*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, methodName: string
): Result[AuthorityDecision, string] =
  if consumerKey(consumer) in runtime.invalidatedConsumers:
    return err("runtime control binding invalidated for " & consumer.moduleInstanceId)
  requireAuthority(runtime, consumer, methodName)

# -- establish_route (local path; remote is Phase 5) --

proc establishRoute*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: EstablishRouteRequest
): Result[EstablishRouteResponse, string] =
  ## 12-step algorithm (RUNTIME §9.3), local path. The consumer is
  ## authenticated and the authority policy evaluated (N1, not a stub allow);
  ## the provider must be a loaded, ready local module instance.
  # N1/N4: authenticate + authorize; reject an invalidated RC binding.
  let decision = ?checkRcInvocation(runtime, consumer, "establish_route")
  # request_key idempotency (consumer-scoped, RUNTIME §9.3): a repeat of the
  # same key returns the previously established routes without re-establishing.
  # A repeat with a different contract (the different-fields check) is
  # rejected as an invalid request.
  let rkKey = consumer.moduleInstanceId & "/" & req.requestKey
  if runtime.requestKeys.hasKey(rkKey):
    # N5: different-fields check (§9.3) — a repeat bound to a different
    # contract is an invalid request, not an idempotent replay.
    if runtime.requestKeyContracts.hasKey(rkKey):
      let stored = runtime.requestKeyContracts[rkKey]
      if cmpBytes(stored, req.contract.schemaRoot) != 0:
        return err("request_key reused with a different contract")
    var routes: seq[RouteRecord]
    for rid in runtime.requestKeys[rkKey]:
      if runtime.routes.hasKey(rid):
        routes.add(runtime.routes[rid].record)
    return ok(EstablishRouteResponse(routes: routes, partial: false))

  # Provider selection: explicit, or the provider matching the contract.
  var provider = ""
  if req.provider.isSome and req.provider.get.provider.len > 0:
    provider = req.provider.get.provider
  if provider.len == 0:
    # find the module whose primary contract matches
    for name in runtime.modules.keys.toSeq:
      let info = runtime.modules[name]
      if info.mode == mmDirect and info.primaryContract.isSome:
        let pc = info.primaryContract.get
        if cmpBytes(pc.schemaRoot, req.contract.schemaRoot) == 0:
          provider = name
          break
  if provider.len == 0:
    return err("no provider matches the requested contract")
  if not runtime.modules.hasKey(provider):
    return err("provider not found: " & provider)
  let info = runtime.modules[provider]

  # Contract validation: the provider must implement the requested contract.
  if info.primaryContract.isNone or
      cmpBytes(info.primaryContract.get.schemaRoot, req.contract.schemaRoot) != 0:
    return err("provider does not implement the requested contract")

  # Route-access scope validation (RUNTIME §9.3): each present list MUST be
  # strictly ascending with no duplicates; the Runtime MUST NOT silently sort
  # or deduplicate a received value.
  ?validateRouteAccess(req.access)

  # Readiness gate: the provider must be ready.
  if info.state != msReady:
    return err("provider is not ready (state: " & stateName(info.state) & ")")

  # The unix host must be serving this provider (the invocation endpoint).
  if runtime.unixHost == nil or runtime.unixHostModule != provider:
    return err("no unix-stream host for provider " & provider)

  # Create the route record + issue the route ticket.
  let routeId = "route-" & $runtime.routes.len
  let targetProvider = ModuleProviderAddress(
    runtimeInstanceId: Opt.some(runtime.runtimeInstanceId), provider: provider
  )
  var rec = RouteRecord(
    route: routeId,
    consumer: consumer,
    targetProvider: targetProvider,
    module: provider,
    instance:
      if info.instanceId.len > 0:
        Opt.some(info.instanceId)
      else:
        Opt.none(ModuleInstanceId),
    expectedContract: Opt.some(req.contract),
    access: req.access,
    state: rsReady,
    invocation: Opt.none(InvocationDescriptor),
    decisionId: Opt.some(decision.decisionId),
    expiresAt: Opt.none(uint64),
    failure: Opt.none(RouteFailure),
  )

  let constraints = TicketConstraints(
    consumer: consumer.moduleInstanceId,
    provider: provider,
    contractRoot: req.contract.schemaRoot,
    routeId: routeId,
    endpoint: runtime.unixHost.socketPath,
    access: ticketAccessOf(req.access),
  )
  let (ticket, _) = ?issueTicket(runtime.ticketStore, constraints)

  rec.invocation = Opt.some(
    InvocationDescriptor(
      kind: "local-transport",
      profile: Opt.some("logos.local.unix-stream"),
      path: Opt.some(runtime.unixHost.socketPath),
      ticket: Opt.some(ticket),
    )
  )

  runtime.routes[routeId] = RouteInfo(record: rec, ticket: ticket)
  runtime.emitRouteEvent(routeId, rsReady, provider, targetProvider, Opt.none(Reason))
  runtime.requestKeys[rkKey] = @[routeId]
  runtime.requestKeyContracts[rkKey] = req.contract.schemaRoot
  ok(EstablishRouteResponse(routes: @[rec], partial: false))

# -- close_route --

proc closeRoute*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: CloseRouteRequest
): Result[CloseRouteResponse, string] =
  discard ?checkRcInvocation(runtime, consumer, "close_route")
  if not runtime.routes.hasKey(req.route):
    return err("route not found: " & req.route)
  let cur = runtime.routes[req.route].record
  # Terminal routes are idempotent: report the current state.
  if isTerminalRouteState(cur.state):
    return ok(CloseRouteResponse(route: req.route, state: cur.state))
  # Close the route (terminal) and revoke its ticket (further calls fail).
  runtime.emitRouteEvent(
    req.route, rsClosed, cur.module, cur.targetProvider, req.reason
  )
  runtime.routes.withValue(req.route, ri):
    ri.record.failure =
      Opt.some(RouteFailure(code: "route-closed", message: req.reason))
    if ri.ticket.len > 0:
      revokeTicket(runtime.ticketStore, blake3Seq(ri.ticket))
  return ok(CloseRouteResponse(route: req.route, state: rsClosed))

# -- renew_route --

proc renewRoute*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: RenewRouteRequest
): Result[RenewRouteResponse, string] =
  discard ?checkRcInvocation(runtime, consumer, "renew_route")
  if not runtime.routes.hasKey(req.route):
    return err("route not found: " & req.route)
  let cur = runtime.routes[req.route].record
  # Terminal routes are never revived (§9.1).
  if isTerminalRouteState(cur.state):
    return err("route is terminal and cannot be renewed: " & routeStateName(cur.state))
  runtime.emitRouteEvent(
    req.route, rsReady, cur.module, cur.targetProvider, Opt.none(Reason)
  )
  let newRec = runtime.routes[req.route].record
  return ok(RenewRouteResponse(route: newRec))

# -- list_modules / list_routes --

proc listModules*(
    runtime: var Runtime, consumer: ModuleInstanceAddress
): Result[ListModulesResponse, string] =
  # N1: authenticate + authorize every RC invocation (RUNTIME §9).
  discard ?checkRcInvocation(runtime, consumer, "list_modules")
  var recs: seq[ModuleRecord]
  for name in runtime.modules.keys.toSeq:
    recs.add(moduleRecordOf(runtime.modules[name]))
  ok(ListModulesResponse(modules: recs, partial: false))

## Observation records omit the invocation material (§9.3).
func routeObservation(rec: RouteRecord): RouteRecord =
  var r = rec
  r.invocation = Opt.none(InvocationDescriptor)
  r

proc listRoutes*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: ListRoutesRequest
): Result[ListRoutesResponse, string] =
  # N1: authenticate + authorize every RC invocation (RUNTIME §9).
  discard ?checkRcInvocation(runtime, consumer, "list_routes")
  var recs: seq[RouteRecord]
  for rid in runtime.routes.keys.toSeq:
    let rec = runtime.routes[rid].record
    if req.module.isSome and rec.module != req.module.get:
      continue
    if req.provider.isSome and rec.targetProvider.provider != req.provider.get.provider:
      continue
    recs.add(routeObservation(rec))
  ok(ListRoutesResponse(routes: recs, partial: false))

# -- start_module / stop_module (idempotent, §9.1) --

proc startModule*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: StartModuleRequest
): Result[StartModuleResponse, string] =
  # N1/N4: authenticate + authorize; reject an invalidated RC binding.
  discard ?checkRcInvocation(runtime, consumer, "start_module")
  if not runtime.modules.hasKey(req.module):
    return err("module not found: " & req.module)
  let info = runtime.modules[req.module]
  # Idempotent: ready returns the current state (no duplicate realization).
  # loaded/unloaded performs the realization init. stopping fails (no implicit
  # restart).
  case info.state
  of msReady:
    return ok(
      StartModuleResponse(
        module: req.module, instance: info.instanceId, state: info.state
      )
    )
  of msLoaded, msUnloaded:
    # N2: perform the realization-specific lifecycle work (the module's `_init`)
    # and only report `ready` if every applicable check succeeds. A module
    # whose `_init` fails MUST NOT be reported `ready` (§3.4).
    let code = info.m.initFn()
    if code != 0:
      runtime.emitModuleEvent(
        req.module, msError, Opt.some(Reason("initialization failed: code " & $code))
      )
      return err("module initialization failed: code " & $code)
    runtime.emitModuleEvent(req.module, msReady, Opt.none(Reason))
    return ok(
      StartModuleResponse(module: req.module, instance: info.instanceId, state: msReady)
    )
  of msStopping:
    return err("module is stopping; start fails (no implicit restart)")
  of msError:
    return err("module is in error state")

proc stopModule*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: StopModuleRequest
): Result[StopModuleResponse, string] =
  # N1/N4: authenticate + authorize; reject an invalidated RC binding.
  discard ?checkRcInvocation(runtime, consumer, "stop_module")
  if not runtime.modules.hasKey(req.module):
    return err("module not found: " & req.module)
  let info = runtime.modules[req.module]
  # Idempotent: stopping/unloaded returns the current state (no duplicate
  # destruction).
  case info.state
  of msStopping, msUnloaded:
    return ok(
      StopModuleResponse(
        module: req.module,
        instance:
          if info.instanceId.len > 0:
            Opt.some(info.instanceId)
          else:
            Opt.none(ModuleInstanceId),
        state: info.state,
      )
    )
  of msReady, msLoaded:
    runtime.emitModuleEvent(req.module, msStopping, Opt.none(Reason))
    # N4: close every route whose consumer is this module instance (§3.4).
    # The stopped instance can no longer consume, so its routes go terminal.
    for rid in runtime.routes.keys.toSeq:
      let rec = runtime.routes[rid].record
      if rec.consumer.runtimeInstanceId == runtime.runtimeInstanceId and
          rec.consumer.moduleInstanceId == info.instanceId:
        if not isTerminalRouteState(rec.state):
          runtime.emitRouteEvent(
            rid,
            rsClosed,
            rec.module,
            rec.targetProvider,
            Opt.some(Reason("consumer module stopped")),
          )
          runtime.routes.withValue(rid, ri):
            ri.record.failure = Opt.some(
              RouteFailure(
                code: "consumer-stopped",
                message: Opt.some(Reason("consumer module stopped")),
              )
            )
            if ri.ticket.len > 0:
              revokeTicket(runtime.ticketStore, blake3Seq(ri.ticket))
    # N4: invalidate the module instance's consumer-bound RC binding; reject
    # any later invocation through it (§3.4).
    runtime.invalidatedConsumers.incl(runtime.runtimeInstanceId & "/" & info.instanceId)
    # Destroy the instance (exactly once).
    if not info.m.destroyFn.isNil:
      info.m.destroyFn()
    runtime.emitModuleEvent(req.module, msUnloaded, Opt.none(Reason))
    return ok(
      StopModuleResponse(
        module: req.module,
        instance:
          if info.instanceId.len > 0:
            Opt.some(info.instanceId)
          else:
            Opt.none(ModuleInstanceId),
        state: msUnloaded,
      )
    )
  of msError:
    return err("module is in error state")

# -- get_readiness --

proc getReadiness*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: GetReadinessRequest
): Result[GetReadinessResponse, string] =
  # N1: authenticate + authorize every RC invocation (RUNTIME §9).
  discard ?checkRcInvocation(runtime, consumer, "get_readiness")
  if not runtime.modules.hasKey(req.module):
    return err("module not found: " & req.module)
  let info = runtime.modules[req.module]
  return ok(
    GetReadinessResponse(
      module: req.module,
      instance:
        if info.instanceId.len > 0:
          Opt.some(info.instanceId)
        else:
          Opt.none(ModuleInstanceId),
      state: info.state,
      reason: info.reason,
    )
  )

# -- remote listener / export (POC: local stub, disabled by default) --

proc listRemoteListeners*(
    runtime: var Runtime, consumer: ModuleInstanceAddress
): ListRemoteListenersResponse =
  ListRemoteListenersResponse(listeners: @[], partial: false)

proc setRemoteListener*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: SetRemoteListenerRequest
): Result[SetRemoteListenerResponse, string] =
  # POC: remote listeners are not enforced (Phase 5). Report the record.
  ok(SetRemoteListenerResponse(listener: req.listener))

proc listProviderExports*(
    runtime: var Runtime,
    consumer: ModuleInstanceAddress,
    req: ListProviderExportsRequest,
): ListProviderExportsResponse =
  ListProviderExportsResponse(exports: @[], partial: false)

proc setProviderExport*(
    runtime: var Runtime, consumer: ModuleInstanceAddress, req: SetProviderExportRequest
): Result[SetProviderExportResponse, string] =
  ok(SetProviderExportResponse(exportRecord: req.exportRecord))
