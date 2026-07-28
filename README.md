# Logos Core POC

Implementation of the [Logos Module Interface specification](https://github.com/logos-co/logos-lips/pull/317).

This repository hosts a **work-in-progress** implementation of a plugin system where modules are shared libraries conforming to a C ABI. Modules can run in-process (as `.so` shared libraries) or remotely (as TCP services), with the **same interface contract** abstracting away the execution boundary from the consumer.

## Quick Start

### 0. Install `nimble`

Download and install [nimble v0.24.1+](https://github.com/nim-lang/nimble/releases/).

No need to install `nim`, `nimble` will deal with it. The `nimble` that ships with `nim` might be old and will probably not work.

### 1. Setup dependencies

```bash
nimble setup -l
```

This installs dependencies into the local `nimbledeps/` directory.

### 2. Build

```bash
nimble build2
```

> [!IMPORTANT]
> `build2` - not `build`!

This produces three artifacts:

- `src/runtime_cli` — CLI runtime interface
- `src/runtime_tui` — Terminal UI
- `src/libshell.so` — Example shell module (command execution)
- `src/librt.so` — Runtime control module (implements LOGOS-MODULE-RUNTIME §9.1)

### 3. Run the CLI with the `loop` command

Use the `loop` command to start the CLI as a TCP host server, loading modules and accepting client connections:

```bash
# Start the CLI as a TCP host, loading the rt (runtime control) and shell modules
./src/runtime_cli loop 8543 "load src/librt.so" "load src/libshell.so"
```

This starts a TCP host on port 8543 with both the runtime control module (`rt`) and shell module (`shell`) loaded. The CLI will keep running to serve clients connecting via TCP.

### 4. Connect clients

In a separate terminal, start the TUI to connect to the running CLI process:

```bash
# Connect to the TCP host (press F4 in the TUI to connect to tcp://127.0.0.1:8543)
./src/runtime_tui
```

You can also use the CLI from a third terminal to call runtime control methods:

```bash
# Connect as a TCP client to list modules
./src/runtime_cli -h 127.0.0.1 -p 8543 list
# Call the shell module's exec method
./src/runtime_cli -h 127.0.0.1 -p 8543 call shell exec command=ls
```

## Modules

| Module | Description |
|---|---|
| `libshell.so` | Example module — `exec` method runs shell commands |
| `librt.so` | Runtime control module — exposes `list_modules`, `start_module`, `stop_module`, `get_readiness`, `list_routes`, `revoke_route` |

## Complete End-to-End Example

Terminal 1 — Start the CLI as a TCP host:

```bash
cd /path/to/logos-core-poc2
nimble setup -l
nimble build2
./src/runtime_cli loop 8543 "load src/librt.so" "load src/libshell.so"
```

Terminal 2 — Interactive TUI (connect to the TCP host):

```bash
./src/runtime_tui
# Press F4 to connect to tcp://127.0.0.1:8543
# Navigate to the shell plugin with arrow keys, press Enter to select it
# Navigate to the `exec` method, press Enter to call it
# Enter parameter values: command=ls, args=
```

## Run Tests

The tests do not necessarily encode _intended_ functionality - instead, they were generated from the implemenation as an automated way to track _changes_ in behavior.

```bash
nimble test
```

## Specifications

This implementation is based on the following specifications (work in progress):

| Spec | Description |
|---|---|
| [Module Interface](https://github.com/logos-co/logos-lips/pull/317) | CDDL schema → C API + CBOR encoding mapping |
| [Module Transport](https://github.com/logos-co/logos-lips/pull/317) | Socket protocol with deterministic CBOR framing |
| [Module Runtime](https://github.com/logos-co/logos-lips/pull/317) | Module loading, lifecycle, dispatch, and TCP host |
| [Module Commitment Model](https://github.com/logos-co/logos-lips/pull/317) | Schema identity and structural hashing |

## License

MIT
