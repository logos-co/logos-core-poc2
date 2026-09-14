# Tests for loading and unloading native modules under the new ABI.

import unittest2
import std/[os, strutils]
import ../src/logos_core/[runtime, shared_modules, modules, cbor_profile]
import results

# Resolve the .so path relative to this tests/ directory
var shellSo = getCurrentDir() / "src" / "libshell.so"
normalizePath(shellSo)

suite "Native module load/unload (new ABI)":
  test "init fails for nonexistent file":
    let res = init("/tmp/nonexistent_module_xyz.so", "shell", true)
    check res.isErr
    check res.error.contains("Module file not found")

  test "init fails for invalid module name":
    let res = init(shellSo, "Bad Name", true)
    check res.isErr
    check res.error.contains("invalid module name")

  test "Runtime.load with native lib":
    var rt = newRuntime()
    let res = rt.load(shellSo, "shell", true)
    check res.isOk
    let (name, version) = res.get
    check name == "shell"
    check version == ""
    check rt.listPlugins().contains("shell")
    rt.shutdown()

  test "Runtime.load rejects an unknown expected name":
    # The shell exports logos_shell_name, so expecting "other" fails at
    # known-name symbol resolution (logos_other_name is absent).
    var rt = newRuntime()
    let res = rt.load(shellSo, "other", true)
    check res.isErr
    check res.error.contains("logos_other_name")
    rt.shutdown()

  test "Runtime.unload removes module":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true)
    check rt.listPlugins().contains("shell")
    let res = rt.unload("shell")
    check res.isOk
    check not rt.listPlugins().contains("shell")
    rt.shutdown()

  test "Runtime.unload nonexistent module fails":
    var rt = newRuntime()
    let res = rt.unload("nope")
    check res.isErr
    check res.error.contains("Plugin not loaded")
    rt.shutdown()

  test "Runtime.load then unload then load again":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true)
    check rt.listPlugins().contains("shell")
    discard rt.unload("shell")
    check not rt.listPlugins().contains("shell")
    let res = rt.load(shellSo, "shell", true)
    check res.isOk
    check rt.listPlugins().contains("shell")
    rt.shutdown()

  test "Runtime.listPlugins returns correct set":
    var rt = newRuntime()
    check rt.listPlugins().len == 0
    discard rt.load(shellSo, "shell", true)
    let plugins = rt.listPlugins()
    check plugins.len == 1
    check plugins[0] == "shell"
    rt.shutdown()

  test "Runtime.shutdown cleans up":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true)
    rt.shutdown()
    check rt.listPlugins().len == 0

  test "Runtime.pluginSchema returns the validated contract document":
    var rt = newRuntime()
    discard rt.load(shellSo, "shell", true)
    let res = rt.pluginSchema("shell")
    check res.isOk
    check res.get.contains("shell.exec")
    rt.shutdown()

  test "Runtime.pluginSchema fails for nonexistent module":
    var rt = newRuntime()
    let res = rt.pluginSchema("nope")
    check res.isErr
    check res.error.contains("Plugin not loaded")
    rt.shutdown()

  test "multi-instance init returns distinct contexts; _destroy exactly once":
    # Drive the low-level loader directly: one accepted binding, two
    # live instances with distinct contexts, each destroyed exactly once.
    var loaded = init(shellSo, "shell", true)
    check loaded.isOk
    var m = move(loaded.get)
    var rt = newRuntime()
    let rc = makeStubRcBinding(addr rt)
    let c1 = m.initInstance(rc, nil, nil, "", @[])
    check c1.isOk
    let c2 = m.initInstance(rc, nil, nil, "", @[])
    check c2.isOk
    check c1.get != c2.get
    check liveInstances(m) == 2
    # both instances dispatch independently
    let p = encodeCbor(
      cborMap(
        (cborValue("command"), cborValue("echo")), (cborValue("args"), cborValue("mi"))
      )
    )
    check m.dispatch(c1.get, "exec", p).isOk
    check m.dispatch(c2.get, "exec", p).isOk
    # destroy each exactly once; a second destroy is rejected
    check m.destroyInstance(c1.get).isOk
    check m.destroyInstance(c1.get).isErr
    check m.destroyInstance(c2.get).isOk
    check m.destroyInstance(c2.get).isErr
    check liveInstances(m) == 0
    m.`=destroy`()
