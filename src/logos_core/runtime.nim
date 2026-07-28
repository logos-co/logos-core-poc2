# src/logos_core/runtime.nim

{.push gcsafe, raises: [].}

import
  ./[modules, rt_types, shared_modules, tcp_modules, tcp_host, tcp_protocols],
  results,
  std/[tables, os, net, sequtils, strutils]

type
  ModuleInfo* = object
    m*: Module
    state*: ModuleState
    instanceId*: string
    remote*: Opt[string]

  RouteInfo* = object
    route*: RouteRecord
    state*: RouteState

  Runtime* = object
    modules*: Table[string, ModuleInfo]
    subscribers*: seq[Socket] # TODO this should be callbacks, not sockets
    tcpHost*: ref TcpHost
    routes*: seq[RouteInfo]

proc newRuntime*(): Runtime =
  Runtime(
    modules: initTable[string, ModuleInfo](),
    subscribers: @[],
    tcpHost: nil,
    routes: @[],
  )

proc registerModule*(runtime: var Runtime, name: string, info: sink ModuleInfo) =
  runtime.modules[name] = info

proc shutdown*(runtime: var Runtime) =
  if runtime.tcpHost != nil:
    stopHost(runtime.tcpHost)
    runtime.tcpHost = nil
  for name in runtime.modules.keys.toSeq:
    try:
      let info = runtime.modules[name]
      if not info.m.destroyFn.isNil:
        info.m.destroyFn()
    except:
      discard
  runtime.modules.clear()

proc load*(runtime: var Runtime, path: string): Result[(string, string), string] =
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
    runtime.registerModule(module.name, ModuleInfo(m: module))
    ok(res)
  else:
    let shared = (ref SharedModule)()
    shared[] = ?SharedModule.init(path)
    let res = (shared.name, shared.version)
    let module = Module(
      name: shared.name,
      host: path,
      schema: shared.schema,
      version: shared.version,
      initFn: proc(): cint =
        shared[].initFn(),
      dispatchFn: proc(
          meth: string, params: openArray[byte]
      ): Result[seq[byte], string] =
        shared[].dispatch(meth, params),
      destroyFn: proc() =
        shared[].destroyFn(),
    )
    runtime.registerModule(module.name, ModuleInfo(m: module))
    ok(res)

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

proc dispatchPlugin*(
    runtime: Runtime, name, methodName: string, params: seq[byte]
): Result[seq[byte], string] =
  try:
    runtime.modules[name].m.dispatchFn(methodName, params)
  except KeyError:
    err("Plugin not loaded: " & name)

proc startTcpHost*(runtime: var Runtime, port: net.Port): Result[net.Port, string] =
  if runtime.tcpHost != nil and runtime.tcpHost.running:
    return err("TCP host already running")
  let runtime = addr runtime
  let hostRes = startHost(
    proc(path: string): Result[(string, string), string] =
      runtime[].load(path),
    proc(name: string): Result[void, string] =
      runtime[].unload(name),
    proc(): seq[string] =
      runtime[].listPlugins(),
    proc(
        plugin: string, methodName: string, params: seq[byte]
    ): Result[seq[byte], string] =
      runtime[].dispatchPlugin(plugin, methodName, params),
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
# Runtime Control Methods (from LOGOS-MODULE-RUNTIME Section 9)
# ============================================================================

proc listModules*(runtime: var Runtime): seq[ModuleRecord] =
  ## Returns module records for all known modules
  result = @[]
  for name, info in runtime.modules.pairs:
    let rec = ModuleRecord(
      module: name,
      instance: Opt.some(info.instanceId),
      state: info.state,
      mode: mmDirect, # TODO: derive from module type (direct vs tcp)
    )
    result.add(rec)

proc startModule*(runtime: var Runtime, name: string): Result[void, string] =
  ## Starts a module record already known to the runtime
  runtime.modules.withValue(name, module):
    return
      if module[].state == msUnloaded:
        # Load and init module
        module[].state = msLoaded
        # TODO: call initFn() when actual init is wired
        module[].state = msReady
        ok()
      else:
        err("Module already loaded (state: " & module[].state.stateName() & ")")
  do:
    return err("Module not found: " & name)

proc stopModule*(runtime: var Runtime, name: string): Result[void, string] =
  ## Stops the selected module instance
  runtime.modules.withValue(name, module):
    return
      if module[].state == msReady:
        module[].state = msStopping
        # TODO: call destroyFn()
        module[].state = msUnloaded
        ok()
      else:
        err("Module not in ready state (state: " & module[].state.stateName() & ")")
  do:
    return err("Module not found: " & name)

proc getReadiness*(
    runtime: Runtime, name: string
): Result[(ModuleState, Opt[Reason]), string] =
  try:
    let state = runtime.modules[name].state
    ok((state, Opt.none(Reason)))
  except KeyError:
    err("Module not found: " & name)

proc listRoutes*(runtime: Runtime): seq[RouteRecord] =
  ## Returns routes filtered by optional module/provider
  result = @[]
  for ri in runtime.routes:
    result.add(ri.route)

proc revokeRoute*(runtime: var Runtime, routeId: string): Result[void, string] =
  ## Revoke a route
  for i in 0 ..< runtime.routes.len:
    if runtime.routes[i].route.route == routeId:
      runtime.routes[i].state = rsRevoked
      return ok()
  return err("Route not found: " & routeId)

proc addRoute*(runtime: var Runtime, route: RouteRecord) =
  ## Add a route to the runtime's route table
  runtime.routes.add(RouteInfo(route: route, state: rsReady))

proc getStateName*(state: ModuleState): string =
  state.stateName()

proc getRouteStateName*(state: RouteState): string =
  state.routeStateName()

proc getModeName*(mode: ModuleMode): string =
  mode.modeName()
