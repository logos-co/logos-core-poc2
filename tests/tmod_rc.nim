# Tests for the Runtime Control module (new ABI, LOGOS-MODULE-RUNTIME §9.3).
#
# The logos_runtime_control module is the Runtime Control provider: it exposes
# the logos.runtime_control.* methods and delegates to the process-wide
# Runtime. Every successful response carries a payload commitment.

import
  unittest2,
  std/[os, strutils, dynlib, tables],
  ../src/logos_core/
    [runtime, modules, cbor_profile, rt_types, hash_profile, shared_modules],
  results

# Resolve the .so path relative to this tests/ directory
var rtSo = getCurrentDir() / "src" / "librt.so"
normalizePath(rtSo)

proc respText(resp: seq[byte], field: string): string =
  let v = decodeCbor(resp)
  let f = v.mapGet(field)
  if f.kind == ckText: f.s else: ""

proc respBool(resp: seq[byte], field: string): bool =
  let v = decodeCbor(resp)
  let f = v.mapGet(field)
  f.kind == ckBool and f.b

proc moduleNames(resp: seq[byte]): seq[string] =
  let v = decodeCbor(resp)
  let modules = v.mapGet("modules")
  for m in modules.items:
    result.add(m.mapGet("module").s)

suite "Runtime Control module (new ABI)":
  test "load validates the call surface":
    var rt = newRuntime()
    let res = rt.load(rtSo, "logos_runtime_control", true)
    check res.isOk
    check rt.listPlugins().contains("logos_runtime_control")
    rt.shutdown()

  test "loader accepts the reserved logos_runtime_control name (N6, RUNTIME §9.3)":
    # The spec names the RC module explicitly: "Its flat runtime module name
    # is `logos_runtime_control`" and `_module = "logos_runtime_control"`.
    # The loader must accept the reserved `logos_*` name (not reject it).
    check validModuleName("logos_runtime_control")
    # A normal (non-Logos) module name is still accepted.
    check validModuleName("shell")
    # Names with the forbidden `_call_` / `_publish_` substrings are rejected.
    check not validModuleName("foo_call_bar")
    check not validModuleName("foo_publish_bar")

  test "list_modules returns the loaded modules":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")
    # Load the shell module so it appears in the listing
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")

    let res = rt.dispatchPlugin("logos_runtime_control", "list_modules", @[])
    check res.isOk
    let v = decodeCbor(res.get)
    let modules = v.mapGet("modules")
    check modules.kind == ckArray
    check modules.items.len >= 2
    # The rt module itself is listed
    var names: seq[string] = @[]
    for m in modules.items:
      names.add(m.mapGet("module").s)
    check "logos_runtime_control" in names
    check "shell" in names
    check respBool(res.get, "partial") == false
    rt.shutdown()

  test "start_module reports ready state":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")

    let params = encodeCbor(cborMap((cborValue("module"), cborValue("shell"))))
    let res = rt.dispatchPlugin("logos_runtime_control", "start_module", params)
    check res.isOk
    let v = decodeCbor(res.get)
    check respText(res.get, "module") == "shell"
    check respText(res.get, "state") == "ready"
    rt.shutdown()

  test "get_readiness reports the module state":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")

    # A freshly loaded module is in the "loaded" state; start_module
    # transitions it to "ready".
    let params = encodeCbor(cborMap((cborValue("module"), cborValue("shell"))))
    let res = rt.dispatchPlugin("logos_runtime_control", "get_readiness", params)
    check res.isOk
    check respText(res.get, "module") == "shell"
    check respText(res.get, "state") == "loaded"
    rt.shutdown()

  test "get_readiness for an unknown module reports error state":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")

    let params = encodeCbor(cborMap((cborValue("module"), cborValue("nope_xyz"))))
    let res = rt.dispatchPlugin("logos_runtime_control", "get_readiness", params)
    check res.isOk
    check respText(res.get, "state") == "error"
    rt.shutdown()

  test "stop_module reports unloaded state":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")

    let params = encodeCbor(cborMap((cborValue("module"), cborValue("shell"))))
    let res = rt.dispatchPlugin("logos_runtime_control", "stop_module", params)
    check res.isOk
    check respText(res.get, "module") == "shell"
    check respText(res.get, "state") == "unloaded"
    rt.shutdown()

  test "list_routes returns an empty route list":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")

    let res = rt.dispatchPlugin("logos_runtime_control", "list_routes", @[])
    check res.isOk
    let v = decodeCbor(res.get)
    let routes = v.mapGet("routes")
    check routes.kind == ckArray
    check routes.items.len == 0
    check respBool(res.get, "partial") == false
    rt.shutdown()

  test "close_route for an unknown route fails":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")

    let params = encodeCbor(cborMap((cborValue("route"), cborValue("no-route-xyz"))))
    let res = rt.dispatchPlugin("logos_runtime_control", "close_route", params)
    check res.isErr
    rt.shutdown()

  test "renew_route is not ready in the POC":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")

    let params = encodeCbor(
      cborMap(
        (cborValue("request_key"), cborValue("k")), (cborValue("route"), cborValue("r"))
      )
    )
    let res = rt.dispatchPlugin("logos_runtime_control", "renew_route", params)
    check res.isErr
    rt.shutdown()

  test "unknown method fails":
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")

    let res = rt.dispatchPlugin("logos_runtime_control", "nope_xyz", @[])
    check res.isErr
    rt.shutdown()

  test "logos.schema introspection returns a schema_response map":
    # INTERFACE §5.1: logos.schema returns a logos.schema_response map with
    # the primary schema document (not a bare namespace string).
    var rt = newRuntime()
    discard rt.load(rtSo, "logos_runtime_control", true).expect("rt loads")

    let res = rt.dispatchPlugin("logos_runtime_control", "logos.schema", @[])
    check res.isOk
    let v = decodeCbor(res.get)
    check v.kind == ckMap
    check v.mapGet("schema").kind == ckText
    check v.mapGet("schema").s.len > 0
    rt.shutdown()

  test "call_surface returns the same bytes on every call (I4)":
    # INTERFACE §2.6: the descriptor MUST be returned as the same bytes on
    # every call; §2.7: the caller MUST NOT free it. dlopen the rt .so and
    # call logos_logos_runtime_control_call_surface twice — same pointer and same bytes.
    let h = loadLib(rtSo)
    check h != nil
    let f = cast[proc(outLen: ptr csize_t): ptr uint8 {.nimcall.}](symAddr(
      h, "logos_logos_runtime_control_call_surface"
    ))
    check f != nil
    var len1, len2: csize_t
    let b1 = f(addr len1)
    let b2 = f(addr len2)
    check b1 != nil
    check b1 == b2 # same static buffer
    check len1 == len2
    check len1 > 0
    var bytes1 = newSeq[byte](len1)
    copyMem(addr bytes1[0], b1, len1)
    var bytes2 = newSeq[byte](len2)
    copyMem(addr bytes2[0], b2, len2)
    check bytes1 == bytes2
    # the caller MUST NOT free the buffer (§2.7); just release the handle
    unloadLib(h)

  test "two instances are independent (per-instance context, N7)":
    # Two separate Runtimes, each loading the rt module. Each rt module
    # instance must control its own Runtime via the ABI opaque context — not
    # a shared process-global pointer (N7: no cross-instance overwrite).
    var rt1 = newRuntime()
    discard rt1.load(rtSo, "logos_runtime_control", true).expect("rt1 loads")
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt1.load(shellSo, "shell", true).expect("shell loads in rt1")

    var rt2 = newRuntime()
    discard rt2.load(rtSo, "logos_runtime_control", true).expect("rt2 loads")
    # rt2 does NOT load the shell module

    # rt1 sees both rt and shell
    let res1 = rt1.dispatchPlugin("logos_runtime_control", "list_modules", @[])
    check res1.isOk
    check "shell" in moduleNames(res1.get)

    # rt2 sees only rt (no cross-instance overwrite from rt1)
    let res2 = rt2.dispatchPlugin("logos_runtime_control", "list_modules", @[])
    check res2.isOk
    check "shell" notin moduleNames(res2.get)

    rt1.shutdown()
    rt2.shutdown()

  test "request_key different-fields check (N5)":
    # RUNTIME §9.3: a request_key reused with a different contract is an
    # invalid request (not an idempotent replay); a repeat with the same
    # contract returns the previously established routes.
    var rt = newRuntime()
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")
    # N1: the consumer is the runtime's bootstrap identity (the host) — an
    # authenticated consumer, not a fabricated module instance.
    let consumer = ModuleInstanceAddress(
      runtimeInstanceId: "local-runtime", moduleInstanceId: "local-runtime"
    )
    discard rt.startModule(consumer, StartModuleRequest(module: "shell")).expect(
        "shell starts"
      )
    # establishRoute requires the unix-stream host to be serving the provider.
    let baseDir = getCurrentDir() / "_n5_unix"
    if dirExists(baseDir):
      if fileExists(baseDir / "provider.sock"):
        removeFile(baseDir / "provider.sock")
      removeDir(baseDir)
    discard rt.startUnixHost(baseDir, "shell").expect("unix host starts")

    # The shell's primary contract root (the provider matching the contract).
    let shellRoot = rt.modules["shell"].primaryContract.get.schemaRoot
    # A distinct 32-byte contract root (no provider matches it).
    var otherRoot = newSeq[byte](32)
    for i in 0 ..< 32:
      otherRoot[i] = cast[byte](i + 1)

    var reqA = EstablishRouteRequest(
      requestKey: "k1",
      contract: SchemaCommitment(schemaRoot: shellRoot),
      cardinality: "single",
      provider: Opt.some(ModuleProviderAddress(provider: "shell")),
      access: RouteAccess(
        methodsAbsent: true, publishEventsAbsent: true, subscribeEventsAbsent: true
      ),
    )
    let resA = rt.establishRoute(consumer, reqA)
    check resA.isOk
    check resA.get.routes.len == 1

    # Same request_key, different contract -> rejected (different-fields).
    var reqB = reqA
    reqB.contract = SchemaCommitment(schemaRoot: otherRoot)
    let resB = rt.establishRoute(consumer, reqB)
    check resB.isErr

    # Same request_key, same contract -> idempotent replay (same route).
    let resC = rt.establishRoute(consumer, reqA)
    check resC.isOk
    check resC.get.routes.len == 1
    check resC.get.routes[0].route == resA.get.routes[0].route

    stopUnixHostForRuntime(rt)
    rt.shutdown()
    if dirExists(baseDir):
      if fileExists(baseDir / "provider.sock"):
        removeFile(baseDir / "provider.sock")
      removeDir(baseDir)

  test "unauthenticated consumer is denied (N1)":
    # RUNTIME §9: RC invocations are accepted only from an authenticated
    # module instance. A consumer that is neither an admitted module instance
    # nor the runtime's bootstrap identity is rejected (not a stub allow).
    var rt = newRuntime()
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")
    # An unauthenticated consumer (not an admitted module, not the bootstrap).
    let bad = ModuleInstanceAddress(
      runtimeInstanceId: "local-runtime", moduleInstanceId: "unknown"
    )
    let denied = rt.listModules(bad)
    check denied.isErr
    # The bootstrap identity (the host) is authenticated.
    let host = ModuleInstanceAddress(
      runtimeInstanceId: "local-runtime", moduleInstanceId: "local-runtime"
    )
    let allowed = rt.listModules(host)
    check allowed.isOk
    rt.shutdown()

  test "stop_module closes the instance's routes and invalidates its RC binding (N4)":
    # RUNTIME §3.4: on stop, Runtime MUST close every route whose consumer is
    # the stopped module instance, and MUST invalidate its consumer-bound RC
    # binding (reject any later invocation through it).
    var rt = newRuntime()
    var shellSo = getCurrentDir() / "src" / "libshell.so"
    normalizePath(shellSo)
    discard rt.load(shellSo, "shell", true).expect("shell loads")
    let host = ModuleInstanceAddress(
      runtimeInstanceId: "local-runtime", moduleInstanceId: "local-runtime"
    )
    let shell = ModuleInstanceAddress(
      runtimeInstanceId: "local-runtime", moduleInstanceId: "shell"
    )
    discard
      rt.startModule(host, StartModuleRequest(module: "shell")).expect("shell starts")
    let baseDir = getCurrentDir() / "_n4_unix"
    if dirExists(baseDir):
      if fileExists(baseDir / "provider.sock"):
        removeFile(baseDir / "provider.sock")
      removeDir(baseDir)
    discard rt.startUnixHost(baseDir, "shell").expect("unix host starts")
    let shellRoot = rt.modules["shell"].primaryContract.get.schemaRoot
    # Establish a route whose consumer is the shell.
    var req = EstablishRouteRequest(
      requestKey: "k4",
      contract: SchemaCommitment(schemaRoot: shellRoot),
      cardinality: "single",
      provider: Opt.some(ModuleProviderAddress(provider: "shell")),
      access: RouteAccess(
        methodsAbsent: true, publishEventsAbsent: true, subscribeEventsAbsent: true
      ),
    )
    let res = rt.establishRoute(shell, req)
    check res.isOk
    let routeId = res.get.routes[0].route
    check rt.routes[routeId].record.state == rsReady
    # Stop the shell (via the host consumer). Its routes close + binding invalidates.
    let stop = rt.stopModule(host, StopModuleRequest(module: "shell"))
    check stop.isOk
    # The route is now terminal (closed).
    check isTerminalRouteState(rt.routes[routeId].record.state)
    # The shell's RC binding is invalidated: a later RC call is rejected.
    let denied = rt.listModules(shell)
    check denied.isErr
    # The host's binding is still valid.
    let allowed = rt.listModules(host)
    check allowed.isOk
    rt.shutdown()
    if dirExists(baseDir):
      if fileExists(baseDir / "provider.sock"):
        removeFile(baseDir / "provider.sock")
      removeDir(baseDir)
