import
  std/[os, net, strutils, tables, sequtils],
  results,
  ./logos_core/[cbor_stuff, schemas, runtime, tcp_modules, tcp_host]

const defaultPort = net.Port(8543)

type
  CliCmd* {.pure.} = enum
    ccHelp
    ccLoad
    ccList
    ccSchema
    ccMethods
    ccCall
    ccStartHost
    ccStopHost
    ccLoop
    ccRun

  CliArgs* = object
    cmd*: CliCmd
    loadPath*: string
    schemaName*: string
    methodName*: string
    callModule*: string
    callMethod*: string
    callArgs*: seq[string]
    hostPort*: net.Port
    runCmds*: seq[string]
    loopCmds*: seq[string] ## commands to run before loop (e.g. load, methods, call)
    remoteHost*: string ## remote TCP host for call (e.g. 127.0.0.1)
    remotePort*: int ## remote TCP port for call

proc printFullUsage() =
  echo "Usage: runtime-cli [options] [command] [options...]"
  echo ""
  echo "Options:"
  echo "  -h HOST   Remote host (for 'call' command)"
  echo "  -p PORT   Remote port (for 'call' command, default: 8543)"
  echo ""
  echo "Commands:"
  echo "  run <cmd> [args...] [&& <cmd> [args...]]"
  echo "    Run one or more chained commands in a single session"
  echo ""
  echo "  load <path>"
  echo "    Load a module (.so file or tcp:// target)"
  echo ""
  echo "  list"
  echo "    List loaded modules"
  echo ""
  echo "  schema <module-name>"
  echo "    Print the CDDL schema of a module"
  echo ""
  echo "  methods <module-name>"
  echo "    List available methods of a module"
  echo ""
  echo "  call <module> <method> [key=value ...]"
  echo "    Call a method with named parameters"
  echo ""
  echo "  start-host [port]"
  echo "    Start the TCP host server (default: 8543)"
  echo ""
  echo "  stop-host"
  echo "    Stop the TCP host server"
  echo ""
  echo "  loop [port]"
  echo "    Start TCP host and keep running to serve clients (default: 8543)"

proc parseArgs(): CliArgs =
  if paramCount() < 1:
    printFullUsage()
    quit(1)

  ## Parse global flags (-h HOST, -p PORT) before the command
  var i = 1
  while i <= paramCount() and paramStr(i).startsWith("-"):
    case paramStr(i).toLowerAscii
    of "-h", "--host":
      if i + 1 <= paramCount():
        result.remoteHost = paramStr(i + 1)
        inc i
      else:
        echo "Error: -h requires a host argument"
        quit(1)
    of "-p", "--port":
      if i + 1 <= paramCount():
        try:
          result.remotePort = parseInt(paramStr(i + 1))
        except:
          echo "Error: invalid port: " & paramStr(i + 1)
          quit(1)
        inc i
      else:
        echo "Error: -p requires a port argument"
        quit(1)
    else:
      break ## unknown flag, stop parsing flags
    inc i

  if i > paramCount():
    echo "Usage: runtime-cli [options] [command] [options...]"
    quit(1)

  ## Now parse the command (at position i)
  let raw = paramStr(i)
  inc i

  case raw
  of "load":
    result.cmd = ccLoad
    if i <= paramCount():
      result.loadPath = paramStr(i)
  of "list":
    result.cmd = ccList
  of "schema":
    result.cmd = ccSchema
    if i <= paramCount():
      result.schemaName = paramStr(i)
  of "methods":
    result.cmd = ccMethods
    if i <= paramCount():
      result.methodName = paramStr(i)
  of "call":
    result.cmd = ccCall
    if i <= paramCount():
      result.callModule = paramStr(i)
      inc i
    if i <= paramCount():
      result.callMethod = paramStr(i)
      inc i
    while i <= paramCount():
      result.callArgs.add(paramStr(i))
      inc i
  of "start-host":
    result.cmd = ccStartHost
    if i <= paramCount():
      try:
        result.hostPort = net.Port(parseInt(paramStr(i)))
      except:
        result.hostPort = defaultPort
    else:
      result.hostPort = defaultPort
  of "stop-host":
    result.cmd = ccStopHost
  of "loop":
    result.cmd = ccLoop
    if i <= paramCount():
      try:
        result.hostPort = net.Port(parseInt(paramStr(i)))
      except:
        result.hostPort = defaultPort
      inc i
    while i <= paramCount():
      result.loopCmds.add(paramStr(i))
      inc i
  of "run":
    result.cmd = ccRun
    var currentCmds: seq[string] = @[]
    while i <= paramCount():
      let arg = paramStr(i)
      if arg == "&&" and currentCmds.len > 0:
        result.runCmds.add(currentCmds.join(" "))
        currentCmds = @[]
      else:
        currentCmds.add(arg)
      inc i
    if currentCmds.len > 0:
      result.runCmds.add(currentCmds.join(" "))
  of "help", "--help":
    result.cmd = ccHelp
  else:
    echo "Unknown command: " & paramStr(i)
    quit(1)

proc doLoad(rt: var Runtime, path: string): Result[void, string] =
  let loaded = rt.load(path)
  if loaded.isOk:
    echo "  Loaded: ", loaded.get[0], " (version ", loaded.get[1], ")"
    ok()
  else:
    err("Load failed: " & loaded.error)

proc doList(rt: Runtime): Result[void, string] =
  let plugins = rt.listPlugins()
  if plugins.len == 0:
    echo "  No modules loaded."
  else:
    echo "  Loaded modules:"
    for name in plugins:
      echo "  - ", name
  ok()

proc doSchema(rt: Runtime, name: string): Result[void, string] =
  let schemaRes = rt.pluginSchema(name)
  if schemaRes.isOk:
    echo "  Schema for '", name, "':"
    echo schemaRes.get
    ok()
  else:
    err("Plugin not found: " & schemaRes.error)

proc doMethods(rt: Runtime, name: string): Result[void, string] =
  let schemaRes = rt.pluginSchema(name)
  if schemaRes.isErr:
    return err("Plugin not found: " & schemaRes.error)
  let schema = schemaRes.get
  let methods = extractMethodsFromSchema(schema)
  if methods.len == 0:
    echo "  No methods found in '", name, "'."
  else:
    echo "  Methods in '", name, "':"
    for m in methods:
      let params = extractMethodParams(schema, m)
      if params.len > 0:
        let paramStr = params.mapIt(it.name & ": " & it.typeName).join(", ")
        echo "    - " & m & " (" & paramStr & ")"
      else:
        echo "    - " & m
  ok()

proc doCall(
    rt: Runtime, moduleName: string, methodName: string, argStrs: seq[string]
): Result[void, string] =
  let schemaRes = rt.pluginSchema(moduleName)
  if schemaRes.isErr:
    return err("Plugin not found: " & schemaRes.error)
  let schema = schemaRes.get

  let methods = extractMethodsFromSchema(schema)
  if methodName notin methods:
    return
      err("Method '" & methodName & "' not found. Available: " & methods.join(", "))

  var params = extractMethodParams(schema, methodName)
  var args = initOrderedTable[string, string]()
  for arg in argStrs:
    let eqIdx = arg.find('=')
    if eqIdx > 0:
      let key = arg[0 ..< eqIdx].strip().toLowerAscii
      let value = arg[eqIdx + 1 ..< arg.len]
      args[key] = value
    else:
      return err("Invalid parameter format: '" & arg & "'. Expected key=value")

  for i in 0 ..< params.len:
    if args.hasKey(params[i].name.toLowerAscii):
      params[i].value = args[params[i].name.toLowerAscii]

  let cborParams = buildCborParams(params).valueOr:
    return err("Parameter error: " & error)

  let dispatch = rt.dispatchPlugin(moduleName, methodName, cborParams).valueOr:
    return err("Dispatch failed: " & error)

  let decoded = Cbor.decode(dispatch, CborValueRef)
  echo "  Result:"
  echo decoded
  ok()

proc doRemoteCall(
    target: string, moduleName: string, methodName: string, argStrs: seq[string]
): Result[void, string] =
  ## Connect to a remote TCP host and dispatch a call via dispatch_plugin
  ## The TCP host exposes dispatch_plugin(plugin, methodName, payload) to route
  ## calls to loaded modules. See AGENTS.md TCP Dispatch Pattern.
  let tcpMod = TcpModule.init(target).valueOr:
    return err("Failed to connect to " & target & ": " & error)

  ## Build the method params CBOR payload (empty for no-param methods)
  var cborParams = initOrderedTable[string, CborValueRef]()
  for arg in argStrs:
    let eqIdx = arg.find('=')
    if eqIdx > 0:
      let key = arg[0 ..< eqIdx].strip().toLowerAscii
      let value = arg[eqIdx + 1 ..< arg.len]
      cborParams[key] = CborValueRef(kind: CborValueKind.String, strVal: value)

  ## Build the dispatch_plugin params using Nim object directly
  let dispatchParams = DispatchPluginParams(
    plugin: moduleName, methodName: methodName, payload: Cbor.encode(cborParams)
  )

  ## Send via dispatch_plugin
  let dispatch = tcpMod.dispatch("dispatch_plugin", Cbor.encode(dispatchParams)).valueOr:
    tcpMod.destroy()
    return err("Remote dispatch_plugin failed: " & error)

  tcpMod.destroy()
  let decoded = Cbor.decode(dispatch, CborValueRef)
  echo "  Result (remote):"
  echo decoded
  ok()

proc doStartHost(rt: var Runtime, port: net.Port): Result[void, string] =
  let res = rt.startTcpHost(port)
  if res.isOk:
    echo "  TCP host listening on port ", res[]
    ok()
  else:
    err("Failed to start TCP host: " & res.error)

proc doStopHost(rt: var Runtime): Result[void, string] =
  let res = rt.stopTcpHost()
  if res.isOk:
    echo "  TCP host stopped."
    ok()
  else:
    err("Failed to stop TCP host: " & res.error)

proc parseSingleCmd(line: string): (CliCmd, seq[string]) =
  ## Parse a single command line into (command, args)
  let parts = line.strip().splitWhitespace()
  if parts.len == 0:
    return (ccHelp, @[])
  case parts[0].toLowerAscii
  of "load":
    result = (ccLoad, @[parts[1]] & parts[1 ..< parts.len].toSeq)
  of "list":
    result = (ccList, @[])
  of "schema":
    result = (ccSchema, @[parts[1]])
  of "methods":
    result = (ccMethods, @[parts[1]])
  of "call":
    result = (
      ccCall,
      @["--module=" & parts[1], "--method=" & parts[2]] & parts[3 ..< parts.len].toSeq,
    )
  of "start-host":
    if parts.len > 1:
      result = (ccStartHost, @[parts[1]])
    else:
      result = (ccStartHost, @[])
  of "stop-host":
    result = (ccStopHost, @[])
  else:
    result = (ccHelp, @[])

proc executeCmd(rt: var Runtime, cmd: CliCmd, args: seq[string]): Result[void, string] =
  case cmd
  of ccHelp:
    echo "  No help available for 'help' (type 'runtime-cli' alone for full usage)"
    ok()
  of ccLoad:
    if args.len < 1:
      return err("Usage: load <path>")
    doLoad(rt, args[0])
  of ccList:
    doList(rt)
  of ccSchema:
    if args.len < 1:
      return err("Usage: schema <module-name>")
    doSchema(rt, args[0])
  of ccMethods:
    if args.len < 1:
      return err("Usage: methods <module-name>")
    doMethods(rt, args[0])
  of ccCall:
    var modName = ""
    var methodName = ""
    var extraArgs: seq[string] = @[]
    for a in args:
      if a.startsWith("--module="):
        modName = a[9 ..< a.len]
      elif a.startsWith("--method="):
        methodName = a[9 ..< a.len]
      elif not a.startsWith("--"):
        extraArgs.add(a)
    if modName.len == 0 or methodName.len == 0:
      return err("Usage: call <module> <method> [key=value ...]")
    doCall(rt, modName, methodName, extraArgs)
  of ccStartHost:
    var port = defaultPort
    for a in args:
      if a.startsWith("--port="):
        port = net.Port(parseInt(a[7 ..< a.len]))
    doStartHost(rt, port)
  of ccStopHost:
    doStopHost(rt)
  else:
    err("Unknown command")

proc doRun(rt: var Runtime, cmds: seq[string]) =
  echo "=== Logos Runtime CLI (run mode) ==="
  var cmdIdx = 0
  for cmdLine in cmds:
    # Split on && in case multiple chained commands are in one arg
    let subCmds = cmdLine.split("&&")
    for subCmd in subCmds:
      let trimmed = subCmd.strip()
      if trimmed.len == 0:
        continue
      inc cmdIdx
      echo ""
      echo ">> Cmd ", cmdIdx, ": ", trimmed
      let (cmd, cmdArgs) = parseSingleCmd(trimmed)
      let res = executeCmd(rt, cmd, cmdArgs)
      if res.isErr:
        echo "  ERROR: " & res.error
        echo "  Stopping run at command ", cmdIdx
        return

proc main() =
  let args = parseArgs()
  var rt = newRuntime()
  defer:
    rt.shutdown()

  case args.cmd
  of ccHelp:
    printFullUsage()
  of ccRun:
    if args.runCmds.len == 0:
      echo "  No commands provided. Usage:"
      echo "    runtime-cli run \"load libshell.so\" && \"methods shell\" && \"call shell exec command=ls\""
      quit(1)
    doRun(rt, args.runCmds)
  of ccLoad:
    if args.loadPath.len == 0:
      echo "Usage: runtime-cli load <path>"
      quit(1)
    let res = doLoad(rt, args.loadPath)
    if res.isErr:
      quit("Load failed: " & res.error)
  of ccList:
    let res = doList(rt)
    if res.isErr:
      quit("Error: " & res.error)
  of ccSchema:
    if args.schemaName.len == 0:
      echo "Usage: runtime-cli schema <module-name>"
      quit(1)
    let res = doSchema(rt, args.schemaName)
    if res.isErr:
      quit("Error: " & res.error)
  of ccMethods:
    if args.methodName.len == 0:
      echo "Usage: runtime-cli methods <module-name>"
      quit(1)
    let res = doMethods(rt, args.methodName)
    if res.isErr:
      quit("Error: " & res.error)
  of ccCall:
    if args.callModule.len == 0 or args.callMethod.len == 0:
      echo "Usage: runtime-cli call <module> <method> [key=value ...]"
      quit(1)
    ## Check if remote host specified
    if args.remoteHost.len > 0:
      let port =
        if args.remotePort > 0:
          $args.remotePort
        else:
          "8543"
      let target = "tcp://" & args.remoteHost & ":" & port
      let res = doRemoteCall(target, args.callModule, args.callMethod, args.callArgs)
      if res.isErr:
        quit("Error: " & res.error)
    else:
      let res = doCall(rt, args.callModule, args.callMethod, args.callArgs)
      if res.isErr:
        quit("Error: " & res.error)
  of ccStartHost:
    let res = doStartHost(rt, args.hostPort)
    if res.isErr:
      quit("Error: " & res.error)
  of ccLoop:
    let hostRes = rt.startTcpHost(args.hostPort)
    if hostRes.isErr:
      quit("Error: " & hostRes.error)
    echo "  TCP host listening on port " & $hostRes[].int
    echo "  Running initial commands..."
    for cmdLine in args.loopCmds:
      let (cmd, cmdArgs) = parseSingleCmd(cmdLine)
      let res = executeCmd(rt, cmd, cmdArgs)
      if res.isErr:
        echo "  ERROR: " & res.error
        echo "  Continuing anyway..."
    echo "  Initial commands done. Ready to serve clients."
    echo "  Press Ctrl-C to stop."
    # Keep the process alive, accepting TCP connections
    # Use a blocking sleep loop instead of stdin to avoid issues with
    # non-interactive shells where stdin may be empty/closed
    while true:
      sleep(1000) # Sleep 1 second at a time
  of ccStopHost:
    let res = doStopHost(rt)
    if res.isErr:
      quit("Error: " & res.error)

when isMainModule:
  main()
