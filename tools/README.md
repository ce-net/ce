# Dev tools

## `ce-build` — build/test/run a repo on a remote CE node

Dev laptops run out of disk and RAM; the mesh has nodes that don't. `ce-build` offloads cargo work
onto a CE node (the Hetzner relay by default) in a sandboxed `rust` container, instead of melting
the laptop. Run it from the workspace root (`~/ce-net`):

```sh
ce/tools/ce-build <repo-path> [cargo subcommand + args...]   # default: test

ce/tools/ce-build ce-ratio test
ce/tools/ce-build web/ce-hub test
ce/tools/ce-build ce-watch "build --locked"
```

- **Workspace-aware:** if the repo's `Cargo.toml` has `path = "../sibling"` deps, the sibling is
  synced alongside it so the relative layout resolves on the remote (one level deep).
- **Incremental:** the cargo registry and a per-repo target dir are persistent volumes on the node,
  so re-builds are fast and deps aren't re-downloaded.
- **Exit code is cargo's**, so it composes in scripts and CI.

Env:
- `CE_BUILD_NODE` — ssh target of the build node (default `root@178.105.145.170`, the relay).
- `CE_BUILD_IMAGE` — rust image (default `rust:1-bookworm`, has gcc/build-essential).

### Why not local / why not CI?
Local builds of the heavy wasmtime `ce` node need ~12 GB and don't fit on a 13 GB laptop volume.
The relay has 53 GB and Docker. Light crates (apps, SDKs, `ce-hub`, `ce-watch`) build there
comfortably; the heavy `ce` node (RAM-hungry wasmtime/cranelift) still wants CI or a bigger box.

### Roadmap: make it CE-native
`ce-build` currently uses raw SSH + Docker. The proper dogfood is `ce exec <node> --image rust --
cargo build` over the mesh — that needs the laptop→node **capability grant** set up and `ce exec`
to mount synced source. Wiring `ce-build` through `ce sync` + `ce exec` (so it's CE-on-CE, not SSH)
is the next step.
