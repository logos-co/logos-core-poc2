# Tests for dispatching methods through the runtime

import
  unittest2,
  std/[os, strutils],
  ../src/logos_core/[runtime, modules, cbor_stuff],
  cbor_serialization,
  cbor_serialization/std/tables,
  results

# Resolve the .so path relative to this tests/ directory
var shellSo = getCurrentDir() / "src" / "libshell.so"
normalizePath(shellSo)

suite "Runtime dispatch (shell module)":
  test "dispatchPlugin with ls command returns files":
    var rt = newRuntime()
    discard rt.load(shellSo).expect("shell gets loaded")

    # Build CBOR params: {"command": "ls", "args": "/"}
    var paramMap = initOrderedTable[string, CborValueRef]()
    paramMap["command"] = CborValueRef(kind: CborValueKind.String, strVal: "ls")
    paramMap["args"] = CborValueRef(kind: CborValueKind.String, strVal: "/")
    let cborParams = Cbor.encode(paramMap)

    let res = rt.dispatchPlugin("shell", "exec", cborParams)
    check res.isOk
    let output = res.get

    # Verify the output contains some files
    check output.len > 0

    # Decode the response as a string (it's the raw stdout from ls /)
    let outputStr = cast[cstring](addr output[0])
    check $outputStr != ""
    check $outputStr != "Error: Failed to execute command"

    rt.shutdown()

  test "dispatchPlugin with pwd returns a path":
    var rt = newRuntime()
    discard rt.load(shellSo).expect("shell gets loaded")

    var paramMap = initOrderedTable[string, CborValueRef]()
    paramMap["command"] = CborValueRef(kind: CborValueKind.String, strVal: "pwd")
    paramMap["args"] = CborValueRef(kind: CborValueKind.String, strVal: "")
    let cborParams = Cbor.encode(paramMap)

    let res = rt.dispatchPlugin("shell", "exec", cborParams)
    check res.isOk
    let output = res.get
    check output.len > 0

    let outputStr = cast[cstring](addr output[0])
    check $outputStr != ""
    check $outputStr != "Error: Failed to execute command"

    rt.shutdown()

  test "dispatchPlugin nonexistent plugin fails":
    var rt = newRuntime()
    let res = rt.dispatchPlugin("nope", "exec", @[])
    check res.isErr
    check res.error.contains("Plugin not loaded")
    rt.shutdown()

  test "dispatchPlugin nonexistent method fails":
    var rt = newRuntime()
    discard rt.load(shellSo).expect("shell gets loaded")

    var paramMap = initOrderedTable[string, CborValueRef]()
    paramMap["command"] = CborValueRef(kind: CborValueKind.String, strVal: "echo")
    paramMap["args"] = CborValueRef(kind: CborValueKind.String, strVal: "hello")
    let cborParams = Cbor.encode(paramMap)

    let res = rt.dispatchPlugin("shell", "nope", cborParams)
    check res.isErr
    rt.shutdown()
