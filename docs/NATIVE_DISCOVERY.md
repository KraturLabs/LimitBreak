# Runtime discovery architecture

The unified x86 DLL discovers a supported FFXiMain memory system during startup.
`320` requests expansion; `discover` validates without patching game code.
Both modes use the same bounded semantic rules in `tools/discovery_rules.py`,
generated into a native header and decoded with statically linked Capstone.

## Discovery and validation

The memory-query hook calls the original function and preserves its result and
last-error value. A small decoded return-site prefilter limits discovery to the
recognized initializer shape. The caller must belong to the loaded FFXiMain.dll.
A stable PE32 snapshot must yield exactly one complete validated graph:

- Initializer calculation, equal cap operands, internal branches and fallback.
- Five pool wrappers, shared builder, aligned headers and terminal sentinels.
- Resource selector route, reverse allocator, free-list/split/null-return rules
  and allocation-size helper.
- Shared initial/fallback backing wrapper, CRT retry and HeapAlloc relationship.
- Writable non-executable pool globals and complete layout or uninitialized state.

Import relationships and derived addresses establish compatibility; client names,
file hashes and fixed module-relative patch addresses do not. Bounds, instruction
and read budgets limit the search. Missing, changing or ambiguous structures
refuse rather than selecting a best guess.

## Startup patch transaction

Expansion requires the actual query return to match discovery, both stock caps,
at least 384 MiB reported physical memory and all five pool globals still zero.
The derived continuation bytes and globals are rechecked immediately before
changing only the two cap operands from 256 to 384. This yields a 320 MiB first
arena, using the original allocator and allocation-failure path.

The transaction verifies bytes, flushes the instruction cache and restores each
memory region's original protection. Failure attempts verified rollback;
unverifiable rollback terminates to avoid a partial patch. Query passthrough,
callback/module pinning and startup-only lifecycle remain active. Restart without
the plugin is the only way to return an initialized arena to stock.

## One-time layout verification

The first post-patch present reads all five discovered bounds. Global-order
budgets are 320 MiB, 10 MiB, 16 MiB, 4 KiB and 4 KiB; physical order is 0,1,3,2,4.
Each sentinel span is its budget minus 144 bytes. Alignment, address overflow,
sentinel bounds and exact sibling spacing are checked.

The complete target layout succeeds. A complete 64 MiB first-arena layout is
recognized as allocation fallback, not successful expansion. A stock 192 MiB,
mixed, malformed or unreadable result is structural failure. Failure outcomes
log and warn once; they do not repair, resize, terminate or repeatedly monitor
an initialized pool. See README.md for user-facing status names.

## Limitations

Recognized instruction families are deliberately bounded. A client/compiler
change can require new validated rules; one DLL does not imply every build works.
Discovery is not a general x86 emulator. A matched layout does not prove allocator
contents, future allocation success, leak freedom, GPU behavior or every game
subsystem safe. Larger finite pools can exhaust or fragment, and backing consumes
additional process address space. Automated tests do not force every OS write,
protection or rollback failure, nor establish live warning visibility.
