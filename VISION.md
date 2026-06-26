# ce-net — Vision

## The ambition

ce-net is being built to become a **global supercomputer that anyone can access** — a single,
open, participant-owned fabric where the world's idle compute is pooled and made available to
everyone, not rented out by a handful of cloud providers.

The goal is that **compute infrastructure, content, applications, games, LLMs, and research**
all run on, and are reachable through, one mesh that no single company owns:

- **Compute infrastructure** — any device, from a phone to a GPU rig to a datacenter node, can
  join, donate cycles, and draw on the pool. Capacity is discovered and priced by the network,
  not gated behind an account with a credit card.
- **Content and apps** — applications, sites, and data are addressed and served over the mesh,
  resilient to any one host going away, reachable from anywhere a peer can reach a peer.
- **Games and interactive systems** — latency-aware placement and a real-time transport let
  interactive and multiplayer workloads run on the same fabric as batch compute.
- **LLMs and AI** — inference and training shard across heterogeneous, donated hardware, so
  capable models can run without depending on one vendor's datacenter.
- **Research** — large computations and open datasets get a substrate that is cheap to reach,
  hard to censor, and owned by its participants.

The economic model makes this sustainable rather than charitable: **donate compute, earn
credits; spend credits to run your own work.** Those who only extract — closed, proprietary,
for-profit users who give nothing back — fund the commons through commercial licensing
(`LICENSING.md`), and that revenue is bound to the mission (`STEWARDSHIP.md`).

## Why it can work

A global supercomputer does not require new datacenters. The hardware already exists — it sits
idle in billions of devices. What has been missing is a **trustless substrate** that lets
strangers safely share compute without a central operator: identity, an economy that settles
without a bank, a mesh that reaches devices behind NAT, sandboxing that contains untrusted work,
and a capability system that authorizes access without an allowlist. ce-net is that substrate.

Each crate in this workspace is one load-bearing piece of that substrate. Its `//!` header
explains both what it does and **how it moves ce-net toward the global supercomputer.**

## The principles that keep it open

1. **Owned by participants, not a company.** Held in trust for the mission, never relicensed
   permissively, never sold to an extractive acquirer (`STEWARDSHIP.md`).
2. **Free for the open commons.** Open, transparent, non-extractive use is free under AGPL-3.0.
3. **Funded by extraction.** Those who close it off and profit pay, and that funds expansion.
4. **Mesh-first and device-agnostic.** Any device can join; no stored ip:port, no central
   gatekeeper, no required cloud account.

This file is the canonical statement of the ambition. Crate and module docs reference it rather
than repeat it.
