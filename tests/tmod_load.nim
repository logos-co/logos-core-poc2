# Tests for loading and unloading shared library modules

import unittest2
import std/[os, strutils, tables]
import ../src/logos_core/[runtime, shared_modules, modules]
import results

# Resolve the .so path relative to this tests/ directory
var shellSo = getCurrentDir() / "src" / "libshell.so"
normalizePath(shellSo)

suite "Shared module load/unload":
  test "SharedModule.init fails for nonexistent file":
    let res = SharedModule.init("/tmp/nonexistent_module_xyz.so")
    check res.isErr
    check res.error.contains("Module file not found")

  test "Runtime.load with shared lib":
    var rt = newRuntime()
    let res = rt.load(shellSo)
    check res.isOk
    let (name, version) = res.get
    check name == "shell"
    check version == "1.0"
    check rt.listPlugins().contains("shell")
    rt.shutdown()

  test "Runtime.unload removes module":
    var rt = newRuntime()
    discard rt.load(shellSo)
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
    discard rt.load(shellSo)
    check rt.listPlugins().contains("shell")
    discard rt.unload("shell")
    check not rt.listPlugins().contains("shell")
    let res = rt.load(shellSo)
    check res.isOk
    check rt.listPlugins().contains("shell")
    rt.shutdown()

  test "Runtime.listPlugins returns correct set":
    var rt = newRuntime()
    check rt.listPlugins().len == 0
    discard rt.load(shellSo)
    let plugins = rt.listPlugins()
    check plugins.len == 1
    check plugins[0] == "shell"
    rt.shutdown()

  test "Runtime.shutdown cleans up":
    var rt = newRuntime()
    discard rt.load(shellSo)
    rt.shutdown()
    check rt.modules.len == 0

  test "Runtime.pluginSchema returns valid schema":
    var rt = newRuntime()
    discard rt.load(shellSo)
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
