# Package

version = "0.1.0"
author = "Jacek Sieka"
description = "logos core CBOR poc"
license = "MIT"
srcDir = "src"
bin = @[]

# Dependencies

requires "nim >= 2.2.10"
requires "chronos >= 4.4.0"
requires "cbor_serialization"
requires "illwill"
requires "https://github.com/arnetheduck/nim-blake3-c.git"

task build2, "Build that can do .so":
  exec "nim c src/runtime_cli"
  exec "nim c src/runtime_tui"
  exec "nim c src/shell"
  exec "nim c src/rt"

task test, "Run unit tests + conformance vectors; continue past failures":
  # Runs every test, continuing past a failing one (the default nimble test
  # task stops at the first failure). Exits nonzero if any test fails.
  # Each conformance vector exits nonzero on failure, so `exec` propagates it.
  var failures = newSeq[string]()
  proc runOne(name, srcFile, outBin: string) =
    echo "=== " & name & " ==="
    try:
      exec "nim c --hints:off --path:src -o:" & outBin & " " & srcFile
      exec outBin
    except:
      echo "FAIL: " & name
      failures.add(name)
  # unit tests (tests/)
  runOne("tmod_dispatch", "tests/tmod_dispatch.nim", "/tmp/logos_tmod_dispatch")
  runOne("tmod_load", "tests/tmod_load.nim", "/tmp/logos_tmod_load")
  runOne("tmod_rc", "tests/tmod_rc.nim", "/tmp/logos_tmod_rc")
  runOne("tmod_tcp", "tests/tmod_tcp.nim", "/tmp/logos_tmod_tcp")
  # conformance vectors (src/_exper/)
  runOne("test_cbor_profile", "src/_exper/test_cbor_profile.nim", "/tmp/logos_test_cbor_profile")
  runOne("test_blake3", "src/_exper/test_blake3.nim", "/tmp/logos_test_blake3")
  runOne("test_cdcddle", "src/_exper/test_cdcddle.nim", "/tmp/logos_test_cdcddle")
  runOne("test_commitment", "src/_exper/test_commitment.nim", "/tmp/logos_test_commitment")
  runOne("test_hash_profile", "src/_exper/test_hash_profile.nim", "/tmp/logos_test_hash_profile")
  runOne("test_route_access", "src/_exper/test_route_access.nim", "/tmp/logos_test_route_access")
  runOne("test_rc_cbor", "src/_exper/test_rc_cbor.nim", "/tmp/logos_test_rc_cbor")
  runOne("t_transport", "src/_exper/t_transport.nim", "/tmp/logos_t_transport")
  if failures.len > 0:
    echo ""
    echo "TESTS: FAILURES PRESENT: " & failures.join(", ")
    quit(1)
  else:
    echo ""
    echo "TESTS: ALL PASS"
