# Project Context

## Current product

LimitBreak is a startup-only Windows x86 Ashita 4.30 POL plugin. One DLL discovers
supported FFXiMain memory-system structures; the sole expanded arena target is
320 MiB, selected by argument `320`. Argument `discover` is read-only validation.
The cap changes from 256 to 384 MiB, growing backing by 128 MiB while preserving
the four sibling budgets and original allocator/fallback behavior.

Compatibility depends on a unique stable semantic graph, loaded-module ownership,
matching query caller, stock caps and five uninitialized pools. The verified
patch transaction restores protections and rolls back failures; unverifiable
rollback is fatal. The first post-patch present classifies the complete five-pool
layout once, distinguishing target capacity, 64 MiB fallback and structural
failure. No live resizing or continuous monitoring; rollback requires full exit
and restart without the POL entry.

## Repository and validation

Runtime sources and shared semantic schemas are authoritative. Reusable native
and Python tests cover patch policy, layout, warnings, reader consistency and
optional caller-supplied image mutations/parity. Generic discovery, occupancy and
boundary tools remain; environment-specific launchers and run histories do not
belong here. Dependencies, captures and build output are ignored.

See [README.md](README.md) for installation/build, [TESTING.md](TESTING.md) for
validation, and [architecture](docs/NATIVE_DISCOVERY.md) for safety and limits.
A never-executed synthetic PE supplies full discovery and discovery-to-patch
integration coverage through 17 portable graph-mutation tests. The 36 optional
real-image/dump tests add compatibility evidence. See TESTING.md for group counts,
coverage mapping and remaining unforced rollback/hook-lifecycle limitations.
Release validation comprises 220 native checks and 73 Python tests: 37 run
without optional inputs; all 73 run when suitable inputs are supplied.

## Limits and next action

Supported instruction families are bounded, not universal client compatibility.
Finite pools can exhaust/fragment; added backing consumes x86 address space.
Automated coverage is not long-term, GPU or all-subsystem safety acceptance.
The release tree is the maintained product baseline, distributed under GPLv3
with the full license in LICENSE. Plugin metadata reports version 1.0.
The v1.0.0 draft package contains limitbreak.dll, README.md and LICENSE, with
separate SHA256SUMS.txt covering the ZIP and DLL. Publication awaits approval.
Next: review the draft release;
changes require a separately scoped task. No additional live testing is queued.
