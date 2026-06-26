# ce-appmgr

The universal app & system manager that makes **`ce` the single root-installed
binary** on a host. Everything else — CE-native apps, arbitrary legacy apps, and
whole systems (Postgres, ffmpeg, a Python service) — is installed, resolved,
sandboxed, and supervised *through* `ce`.

Design and rationale: [`PLAN/ce-app-package-runtime.md`](../../../PLAN/ce-app-package-runtime.md).

## What this crate provides

| Module      | Responsibility |
|-------------|----------------|
| `manifest`  | The `ceapp.toml` format and validation (`oci`/`native`/`wasm`/`recipe` tiers). |
| `platform`  | Host `(os, arch)` -> canonical target (`darwin-arm64`, `linux-amd64`) for native artifact resolution. |
| `resolver`  | Dependency resolution across all tiers into a topologically-ordered install [`Plan`]. |
| `registry`  | ce-hub-backed manifest source (`GET /apps/<name>/ceapp.toml`). |
| `store`     | The on-disk install store and ce-owned launcher shims. |
| `placement` | Global run targets (`self`/`node`/`tag`/`fleet`/`nearest`) and parsing. |
| `instances` | Global instance tracking via ce-hub (register/heartbeat/list) — the `ce app ps` substrate. |
| `ctlapi`    | The per-instance, capability-scoped app-facing control API (apps spawn their own deps securely). |

`ce-appmgr` is the **per-node control-plane agent** that ships inside `ce`; ce-hub
is the **global registry + control plane**. Runtime execution (oci via
`ce-container`, wasm via `ce-wasm`, native spawn), the single daemon supervisor,
global placement over mesh-deploy, and the ce-cap/ce-gov security gates are wired
in the `ce` binary on top of these primitives — this crate is the platform-agnostic
core.

## Runtime tiers (order of universality)

1. **`oci`** — any legacy app/system as an image. Portable by construction,
   gVisor-sandboxed. The default for non-CE software.
2. **`native`** — prebuilt host binary, resolved per `(os, arch)`. For CE-native
   mesh apps that need host/libp2p/Docker access.
3. **`wasm`** — one portable module for all platforms; strongest isolation. Optional.
4. **`recipe`** — build-from-source fallback, cached as an artifact afterwards.

See `manifests/` for worked examples (`postgres.ceapp.toml` = a whole system via
`oci`; `rdev.ceapp.toml` = a CE-native app via `native`).

## CLI (in the `ce` binary)

```
ce app info <name>                manifest + resolved install plan from the registry
ce app install <name> [--on <p>]  resolve graph; --yes records install + writes shim
ce app ls                         locally installed apps
ce app ps [--app <name>]          running instances across the whole mesh (from ce-hub)
ce app uninstall <name>           remove record + artifacts + shim
ce app run <name> [--on <p>] [-- ...]   run in sandbox (execution lands next milestone)

# placement <p> = self (default) | node=<id> | tag=a,b | fleet=<name> | nearest
```

## Status

Core written: manifest format, platform resolution, dependency resolver (cycle +
version checks), ce-hub registry client, install store + shims, global placement,
ce-hub instance-tracking client, and the app-facing CtlAPI types/trait — plus the
`ce app` CLI (`info`/`install`/`ls`/`ps`/`uninstall`/`run`). The M0/M1 core
compiled green with 13 unit tests; the `placement`/`instances`/`ctlapi` modules are
written but compile/test is deferred (local disk pressure). Next: artifact
materialization (blob fetch + verify), oci/wasm/native execution, the single daemon
supervisor + instance heartbeats, global install over mesh-deploy, and the CtlAPI
transport + ce-cap/ce-gov gates. See `../../../PLAN/ce-app-package-runtime.md`.
