# Tests for TCP host and TCP client interop

import
  unittest2,
  std/[os, net, strutils],
  ../src/logos_core/[
    runtime, modules, transport, tcp_protocols, tcp_modules, cbor_stuff, tcp_host,
    rt_types,
  ],
  cbor_serialization,
  cbor_serialization/std/tables,
  results

# Resolve the .so path relative to this tests/ directory
var shellSo = getCurrentDir() / "src" / "libshell.so"
normalizePath(shellSo)

## Helper to extract TransportMessage from Result safely
proc getTransportMsg(res: Result[TransportMessage, string]): TransportMessage =
  if res.isErr:
    check 1 == 2 # should not fail
  res.get

suite "TCP host and client":
  test "TCP host starts on available port":
    var rt = newRuntime()
    let res = rt.startTcpHost(net.Port(0)) # port 0 = let OS pick
    if not res.isOk:
      # Skip if TCP binding fails (e.g., restricted environment)
      skip()
    else:
      let port = res.get
      check int(port) > 0

      # Verify the host is running
      check rt.tcpHost != nil
      check rt.tcpHost.running

      discard rt.stopTcpHost()
    rt.shutdown()

  test "TCP host fails to start when already running":
    var rt = newRuntime()
    let res1 = rt.startTcpHost(net.Port(0))
    check res1.isOk

    let res2 = rt.startTcpHost(res1.get)
    check res2.isErr
    check res2.error.contains("already running")

    discard rt.stopTcpHost()
    rt.shutdown()

  test "TCP host loads shell module via tcp_host.load_plugin":
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    # Connect client
    var client = newSocket(AF_INET, SOCK_STREAM)
    try:
      client.connect("127.0.0.1", net.Port(port))
    except:
      client.close()
      rt.shutdown()
      check 1 == 2 # connection failed

    try:
      # Perform Hello handshake
      let helloReq = HelloRequest(
        protocol: defaultTcpProtocol,
        module: "test_client",
        version: @[1'u32, 0'u32],
        token: @[],
        schema: SchemaCommitment(
          commitmentModel: "logos.commitment-model.2026-06",
          schemaRoot: @[],
          hashProfile: "logos.hash-profile.2026-05",
          hashSuite: "example-suite",
        ),
      )
      let helloMsg = TransportMessage(tag: tHello, payload: Cbor.encode(helloReq))
      discard sendTransportMessage(client, helloMsg)

      let helloResp = getTransportMsg(receiveTransportMessage(client))
      check helloResp.tag == tHello

      # Now load the shell module
      var paramMap = initOrderedTable[string, CborValueRef]()
      paramMap["path"] = CborValueRef(kind: CborValueKind.String, strVal: shellSo)
      let loadParams = Cbor.encode(paramMap)

      let loadReq =
        TransportRequest(callId: 1, methodName: "load_plugin", params: loadParams)
      let loadReqMsg = TransportMessage(tag: tRequest, payload: Cbor.encode(loadReq))
      discard sendTransportMessage(client, loadReqMsg)

      let loadResp = getTransportMsg(receiveTransportMessage(client))
      check loadResp.tag == tResponse
      let loadRespPayload = Cbor.decode(loadResp.payload, TransportResponse)
      check loadRespPayload.responseResult.isSome

      let loadResult = Cbor.decode(loadRespPayload.responseResult.get, seq[string])
      check loadResult.len == 2
      check loadResult[0] == "shell"
      check loadResult[1] == "1.0"

      # Verify list_plugins includes shell
      let listReq = TransportRequest(callId: 2, methodName: "list_plugins", params: @[])
      let listReqMsg = TransportMessage(tag: tRequest, payload: Cbor.encode(listReq))
      discard sendTransportMessage(client, listReqMsg)

      let listResp = getTransportMsg(receiveTransportMessage(client))
      check listResp.tag == tResponse
      let listRespPayload = Cbor.decode(listResp.payload, TransportResponse)
      check listRespPayload.responseResult.isSome
      let plugins = Cbor.decode(listRespPayload.responseResult.get, seq[string])
      check plugins.contains("shell")

      client.close()
    except:
      try:
        client.close()
      except:
        discard
    finally:
      discard rt.stopTcpHost()
      rt.shutdown()

  test "TcpModule dispatches exec via dispatch_plugin":
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    # Load shell module locally on the host (via direct load, not TCP)
    let loadRes = rt.load(shellSo)
    check loadRes.isOk

    # Connect via TcpModule
    let clientRes = TcpModule.init("tcp://127.0.0.1:" & $port)
    check clientRes.isOk
    let client = clientRes.get

    # Verify module info
    check client.moduleName == "tcp_host"
    check client.version.len > 0

    # Build exec params (for the shell module)
    var execParams = initOrderedTable[string, CborValueRef]()
    execParams["command"] = CborValueRef(kind: CborValueKind.String, strVal: "ls")
    execParams["args"] = CborValueRef(kind: CborValueKind.String, strVal: "/")
    let execPayload = Cbor.encode(execParams)

    # Call dispatch_plugin on the TCP host to dispatch to the shell module
    # dispatch_plugin expects: { plugin: tstr, methodName: tstr, payload: bstr }
    var dispatchParams = initOrderedTable[string, CborValueRef]()
    dispatchParams["plugin"] = CborValueRef(kind: CborValueKind.String, strVal: "shell")
    dispatchParams["methodName"] =
      CborValueRef(kind: CborValueKind.String, strVal: "exec")
    dispatchParams["payload"] =
      CborValueRef(kind: CborValueKind.Bytes, bytesVal: execPayload)
    let dispatchPayload = Cbor.encode(dispatchParams)

    let res = client.dispatch("dispatch_plugin", dispatchPayload)
    check res.isOk
    let output = res.get
    check output.len > 0

    # The result is the raw exec output from the shell module
    let outputStr = cast[cstring](addr output[0])
    check $outputStr != ""
    check $outputStr != "Error: Failed to execute command"

    client.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()

  test "Full TCP roundtrip: load via TCP, dispatch via TCP, unload via TCP":
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    var client = newSocket(AF_INET, SOCK_STREAM)
    try:
      client.connect("127.0.0.1", net.Port(port))
    except:
      client.close()
      rt.shutdown()
      check 1 == 2

    try:
      # Hello
      let helloReq = HelloRequest(
        protocol: defaultTcpProtocol,
        module: "test_client",
        version: @[1'u32, 0'u32],
        token: @[],
        schema: SchemaCommitment(
          commitmentModel: "logos.commitment-model.2026-06",
          schemaRoot: @[],
          hashProfile: "logos.hash-profile.2026-05",
          hashSuite: "example-suite",
        ),
      )
      discard sendTransportMessage(
        client, TransportMessage(tag: tHello, payload: Cbor.encode(helloReq))
      )
      let helloResp = getTransportMsg(receiveTransportMessage(client))
      check helloResp.tag == tHello

      # Load shell module via load_plugin
      var loadParamsMap = initOrderedTable[string, CborValueRef]()
      loadParamsMap["path"] = CborValueRef(kind: CborValueKind.String, strVal: shellSo)
      let loadReq = TransportRequest(
        callId: 1, methodName: "load_plugin", params: Cbor.encode(loadParamsMap)
      )
      discard sendTransportMessage(
        client, TransportMessage(tag: tRequest, payload: Cbor.encode(loadReq))
      )
      let loadResp = getTransportMsg(receiveTransportMessage(client))
      let loadPayload = Cbor.decode(loadResp.payload, TransportResponse)
      check loadPayload.responseResult.isSome
      let loadResult = Cbor.decode(loadPayload.responseResult.get, seq[string])
      check loadResult[0] == "shell"

      # Dispatch exec method via dispatch_plugin
      # First build the exec params for the shell module
      var execParamsMap = initOrderedTable[string, CborValueRef]()
      execParamsMap["command"] = CborValueRef(kind: CborValueKind.String, strVal: "ls")
      execParamsMap["args"] = CborValueRef(kind: CborValueKind.String, strVal: "/")
      let execPayload = Cbor.encode(execParamsMap)

      # Then wrap it in DispatchPluginParams: { plugin, methodName, payload }
      var dispatchParamsMap = initOrderedTable[string, CborValueRef]()
      dispatchParamsMap["plugin"] =
        CborValueRef(kind: CborValueKind.String, strVal: "shell")
      dispatchParamsMap["methodName"] =
        CborValueRef(kind: CborValueKind.String, strVal: "exec")
      dispatchParamsMap["payload"] =
        CborValueRef(kind: CborValueKind.Bytes, bytesVal: execPayload)
      let dispatchPluginPayload = Cbor.encode(dispatchParamsMap)

      let dispatchReq = TransportRequest(
        callId: 2, methodName: "dispatch_plugin", params: dispatchPluginPayload
      )
      discard sendTransportMessage(
        client, TransportMessage(tag: tRequest, payload: Cbor.encode(dispatchReq))
      )
      let dispatchResp = getTransportMsg(receiveTransportMessage(client))
      let dispatchRespPayload = Cbor.decode(dispatchResp.payload, TransportResponse)
      check dispatchRespPayload.responseResult.isSome
      let dispatchResult = dispatchRespPayload.responseResult.get
      check dispatchResult.len > 0

      let outputStr = cast[cstring](addr dispatchResult[0])
      check $outputStr != ""
      check $outputStr != "Error: Failed to execute command"

      # Verify the module is loaded via list_plugins
      let listReq = TransportRequest(callId: 3, methodName: "list_plugins", params: @[])
      discard sendTransportMessage(
        client, TransportMessage(tag: tRequest, payload: Cbor.encode(listReq))
      )
      let listResp = getTransportMsg(receiveTransportMessage(client))
      let listPayload = Cbor.decode(listResp.payload, TransportResponse)
      let plugins = Cbor.decode(listPayload.responseResult.get, seq[string])
      check plugins.contains("shell")

      # Unload shell module via unload_plugin
      var unloadParamsMap = initOrderedTable[string, CborValueRef]()
      unloadParamsMap["name"] =
        CborValueRef(kind: CborValueKind.String, strVal: "shell")
      let unloadReq = TransportRequest(
        callId: 4, methodName: "unload_plugin", params: Cbor.encode(unloadParamsMap)
      )
      discard sendTransportMessage(
        client, TransportMessage(tag: tRequest, payload: Cbor.encode(unloadReq))
      )
      let unloadResp = getTransportMsg(receiveTransportMessage(client))
      let unloadPayload = Cbor.decode(unloadResp.payload, TransportResponse)
      check unloadPayload.responseResult.isSome

      client.close()
    except:
      try:
        client.close()
      except:
        discard
    finally:
      discard rt.stopTcpHost()
      rt.shutdown()

  test "Ping/pong via TCP host":
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    var client = newSocket(AF_INET, SOCK_STREAM)
    try:
      client.connect("127.0.0.1", net.Port(port))
    except:
      client.close()
      rt.shutdown()
      check 1 == 2

    try:
      # Hello
      let helloReq = HelloRequest(
        protocol: defaultTcpProtocol,
        module: "ping_client",
        version: @[1'u32, 0'u32],
        token: @[],
        schema: SchemaCommitment(
          commitmentModel: "logos.commitment-model.2026-06",
          schemaRoot: @[],
          hashProfile: "logos.hash-profile.2026-05",
          hashSuite: "example-suite",
        ),
      )
      discard sendTransportMessage(
        client, TransportMessage(tag: tHello, payload: Cbor.encode(helloReq))
      )
      let helloResp = getTransportMsg(receiveTransportMessage(client))
      check helloResp.tag == tHello

      # Ping
      let pingReq = TransportRequest(callId: 1, methodName: "ping", params: @[])
      discard sendTransportMessage(
        client, TransportMessage(tag: tRequest, payload: Cbor.encode(pingReq))
      )
      let pingResp = getTransportMsg(receiveTransportMessage(client))
      let pingPayload = Cbor.decode(pingResp.payload, TransportResponse)
      check pingPayload.responseResult.isSome
      let pong = Cbor.decode(pingPayload.responseResult.get, string)
      check pong == "pong"

      client.close()
    except:
      try:
        client.close()
      except:
        discard
    finally:
      discard rt.stopTcpHost()
      rt.shutdown()

  test "Unknown method returns error via TCP host":
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    var client = newSocket(AF_INET, SOCK_STREAM)
    try:
      client.connect("127.0.0.1", net.Port(port))
    except:
      client.close()
      rt.shutdown()
      check 1 == 2

    try:
      # Hello
      let helloReq = HelloRequest(
        protocol: defaultTcpProtocol,
        module: "test_client",
        version: @[1'u32, 0'u32],
        token: @[],
        schema: SchemaCommitment(
          commitmentModel: "logos.commitment-model.2026-06",
          schemaRoot: @[],
          hashProfile: "logos.hash-profile.2026-05",
          hashSuite: "example-suite",
        ),
      )
      discard sendTransportMessage(
        client, TransportMessage(tag: tHello, payload: Cbor.encode(helloReq))
      )
      let helloResp = getTransportMsg(receiveTransportMessage(client))
      check helloResp.tag == tHello

      # Unknown method
      let badReq = TransportRequest(callId: 1, methodName: "nope", params: @[])
      discard sendTransportMessage(
        client, TransportMessage(tag: tRequest, payload: Cbor.encode(badReq))
      )
      let badResp = getTransportMsg(receiveTransportMessage(client))
      let badPayload = Cbor.decode(badResp.payload, TransportResponse)
      check badPayload.responseError.isSome
      check badPayload.responseError.get.contains("Unknown method")

      client.close()
    except:
      try:
        client.close()
      except:
        discard
    finally:
      discard rt.stopTcpHost()
      rt.shutdown()

  test "TcpModule.dispatch error propagation":
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    let clientRes = TcpModule.init("tcp://127.0.0.1:" & $port)
    check clientRes.isOk
    let client = clientRes.get

    # Call a method that doesn't exist on tcp_host
    let res = client.dispatch("nope", @[])
    check res.isErr
    check res.error.contains("Unknown method")

    client.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()

  # ============================================================================
  # Tests for remote module dispatch via TcpModule + dispatch_plugin
  # ============================================================================
  test "TcpModule dispatches via dispatch_plugin using Nim DispatchPluginParams":
    ## Test that dispatch_plugin works correctly when using Nim's
    ## DispatchPluginParams object (not manual OrderedTable construction).
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    # Load shell module locally on the host
    let loadRes = rt.load(shellSo)
    check loadRes.isOk
    check "shell" in rt.listPlugins()

    # Connect via TcpModule
    let clientRes = TcpModule.init("tcp://127.0.0.1:" & $port)
    check clientRes.isOk
    let client = clientRes.get

    # Build method params and wrap in DispatchPluginParams Nim object
    var execParams = initOrderedTable[string, CborValueRef]()
    execParams["command"] = CborValueRef(kind: CborValueKind.String, strVal: "ls")
    execParams["args"] = CborValueRef(kind: CborValueKind.String, strVal: "/")
    let execPayload = Cbor.encode(execParams)

    let dispatchParams =
      DispatchPluginParams(plugin: "shell", methodName: "exec", payload: execPayload)

    let res = client.dispatch("dispatch_plugin", Cbor.encode(dispatchParams))
    check res.isOk
    let output = res.get
    check output.len > 0
    # The output is a CBOR-encoded map with "output" key
    let decoded = Cbor.decode(output, CborValueRef)
    check decoded.kind == CborValueKind.Object
    check decoded.objVal.hasKey("output")
    let outputVal = decoded.objVal["output"]
    check outputVal.kind == CborValueKind.String
    check outputVal.strVal.len > 0

    client.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()

  test "TcpModule dispatches list_modules via dispatch_plugin":
    ## Test that the rt module's list_modules method works via TCP dispatch.
    var rt = newRuntime()

    # Load the rt module
    var rtSo = getCurrentDir() / "src" / "librt.so"
    normalizePath(rtSo)
    let rtLoadRes = rt.load(rtSo)
    check rtLoadRes.isOk

    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    # Connect via TcpModule
    let clientRes = TcpModule.init("tcp://127.0.0.1:" & $port)
    check clientRes.isOk
    let client = clientRes.get

    # Call list_modules on the rt module via dispatch_plugin
    let dispatchParams = DispatchPluginParams(
      plugin: "rt",
      methodName: "list_modules",
      payload: @[], # list_modules takes no params
    )

    let res = client.dispatch("dispatch_plugin", Cbor.encode(dispatchParams))
    check res.isOk
    check res.get.len > 0

    # Decode the response - it should be a valid CBOR map
    let decoded = Cbor.decode(res.get, CborValueRef)
    check decoded.kind == CborValueKind.Object
    check decoded.objVal.hasKey("modules")

    client.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()

  test "Multiple TcpModule clients can dispatch sequentially":
    ## Test that multiple TCP clients can connect and dispatch sequentially
    ## (server handles clients one at a time).
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    # Load shell module locally
    let loadRes = rt.load(shellSo)
    check loadRes.isOk

    # Client 1: connect, dispatch, disconnect
    let client1Res = TcpModule.init("tcp://127.0.0.1:" & $port)
    check client1Res.isOk
    let client1 = client1Res.get

    var params1 = initOrderedTable[string, CborValueRef]()
    params1["command"] = CborValueRef(kind: CborValueKind.String, strVal: "echo")
    params1["args"] = CborValueRef(kind: CborValueKind.String, strVal: "from_client_1")
    let dispatch1 = DispatchPluginParams(
      plugin: "shell", methodName: "exec", payload: Cbor.encode(params1)
    )

    let res1 = client1.dispatch("dispatch_plugin", Cbor.encode(dispatch1))
    check res1.isOk
    let out1 = Cbor.decode(res1.get, CborValueRef)
    check out1.kind == CborValueKind.Object
    check out1.objVal.hasKey("output")
    check out1.objVal["output"].kind == CborValueKind.String
    client1.destroy()
    # Wait a moment for the server to finish processing client 1
    sleep(100)

    # Client 2: connect, dispatch, disconnect
    let client2Res = TcpModule.init("tcp://127.0.0.1:" & $port)
    check client2Res.isOk
    let client2 = client2Res.get

    var params2 = initOrderedTable[string, CborValueRef]()
    params2["command"] = CborValueRef(kind: CborValueKind.String, strVal: "echo")
    params2["args"] = CborValueRef(kind: CborValueKind.String, strVal: "from_client_2")
    let dispatch2 = DispatchPluginParams(
      plugin: "shell", methodName: "exec", payload: Cbor.encode(params2)
    )

    let res2 = client2.dispatch("dispatch_plugin", Cbor.encode(dispatch2))
    check res2.isOk
    let out2 = Cbor.decode(res2.get, CborValueRef)
    check out2.kind == CborValueKind.Object
    check out2.objVal.hasKey("output")
    check out2.objVal["output"].kind == CborValueKind.String

    client2.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()

  test "TcpModule dispatches unknown plugin returns error":
    ## Test that dispatching to a non-existent plugin returns a proper error.
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    let clientRes = TcpModule.init("tcp://127.0.0.1:" & $port)
    check clientRes.isOk
    let client = clientRes.get

    let dispatchParams = DispatchPluginParams(
      plugin: "nonexistent", methodName: "some_method", payload: @[]
    )

    let res = client.dispatch("dispatch_plugin", Cbor.encode(dispatchParams))
    check res.isErr
    check res.error.contains("Plugin not loaded")

    client.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()

  test "TcpModule dispatches no-param method via tcp_host":
    ## Test dispatching a method that takes no parameters via the TCP host.
    var rt = newRuntime()
    let hostRes = rt.startTcpHost(net.Port(0))
    check hostRes.isOk
    let port = hostRes.get

    let clientRes = TcpModule.init("tcp://127.0.0.1:" & $port)
    check clientRes.isOk
    let client = clientRes.get

    # Call ping on tcp_host directly (built-in, no params needed)
    let res = client.dispatch("ping", @[])
    check res.isOk
    check res.get.len > 0

    let decoded = Cbor.decode(res.get, string)
    check decoded == "pong"

    client.destroy()
    discard rt.stopTcpHost()
    rt.shutdown()
