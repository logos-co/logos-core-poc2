# Tests for dispatching methods through the runtime (new ABI).

import
  unittest2,
  std/[os, strutils],
  ../src/logos_core/[runtime, modules, cbor_profile],
  results

# Resolve the .so path relative to this tests/ directory
var shellSo = getCurrentDir() / "src" / "libshell.so"
normalizePath(shellSo)

proc execParams(command, args: string): seq[byte] =
  encodeCbor(
    cborMap(
      (cborValue("command"), cborValue(command)), (cborValue("args"), cborValue(args))
    )
  )

proc outputOf(resp: seq[byte]): string =
  let v = decodeCbor(resp)
  v.mapGet("output").s

suite "Runtime dispatch (shell module, new ABI)":
  test "dispatchPlugin with echo returns the echoed text":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true).expect("shell gets loaded")

    let res = rt.dispatchPlugin("shell", "exec", execParams("echo", "hello-logos"))
    check res.isOk
    let output = outputOf(res.get)
    check output.contains("hello-logos")

    rt.shutdown()

  test "dispatchPlugin with pwd returns a path":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true).expect("shell gets loaded")

    let res = rt.dispatchPlugin("shell", "exec", execParams("pwd", ""))
    check res.isOk
    let output = outputOf(res.get)
    check output.len > 0

    rt.shutdown()

  test "dispatchPlugin with a failing command reports the shell error":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true).expect("shell gets loaded")

    let res =
      rt.dispatchPlugin("shell", "exec", execParams("definitely_not_a_cmd_xyz", ""))
    check res.isOk
    let output = outputOf(res.get)
    check output.contains("not found")

    rt.shutdown()

  test "dispatchPlugin nonexistent plugin fails":
    var rt = newRuntime()
    let res = rt.dispatchPlugin("nope", "exec", @[])
    check res.isErr
    check res.error.contains("Plugin not loaded")
    rt.shutdown()

  test "dispatchPlugin nonexistent method fails":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true).expect("shell gets loaded")

    let res = rt.dispatchPlugin("shell", "nope", execParams("echo", "x"))
    check res.isErr
    rt.shutdown()

  test "dispatchPlugin with malformed params fails":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true).expect("shell gets loaded")

    # not a map
    let res = rt.dispatchPlugin("shell", "exec", encodeCbor(cborValue("x")))
    check res.isErr
    rt.shutdown()
