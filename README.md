# LimitBreak

LimitBreak is an **Ashita 4.30** plugin for Final Fantasy XI that gives the game more room for loaded resources, especially when using high-resolution texture packs.

FFXI normally has about **192 MB** available in its main resource memory pool. LimitBreak increases that pool to **320 MB**.

The main reason for doing this is modern texture replacement. A 4× upscale turns a 512×512 texture into 2048×2048, which is 16 times as many pixels. Load enough large textures at once, especially around lots of players, equipment, monsters, and effects, and stock FFXI can run out of usable space in this pool and crash.

LimitBreak gives those resources more breathing room without replacing FFXI's allocator or redesigning how the game manages memory.

## Requirements

- **Ashita 4.30 only**
- Windows
- 32-bit FFXI client
- Must load when FFXI starts

LimitBreak does **not** support Ashita 4.16 or Windower.

## What it helps with

LimitBreak is mainly intended for players using larger replacement textures, especially **2× and 4× texture packs**.

Stock FFXI was never designed around thousands of modern high-resolution replacements being loaded at once. In heavy scenes, its normal resource pool can become exhausted or too fragmented to satisfy another large allocation.

LimitBreak raises that pool from about **192 MB to 320 MB**, giving FFXI substantially more room before it reaches that point.

This does not make FFXI unlimited or crash-proof. It simply raises one of the practical limits that high-resolution texture packs can hit.

The 320 MB target was chosen as a balance: enough extra headroom for heavy texture use without reserving more of FFXI's limited 32-bit address space than appeared useful in testing.

## Installation

LimitBreak must be loaded as a **POL plugin** during startup. It cannot be enabled after FFXI is already running because the resource pools are created near the beginning of startup.

With FFXI closed, copy `limitbreak.dll` into Ashita's `polplugins` folder.

Then add these entries to the Ashita boot profile you use to launch FFXI:

```ini
[ashita.polplugins]
limitbreak = 1

[ashita.polplugins.args]
limitbreak = 320
```

Launch the game normally.

To disable LimitBreak, completely exit FFXI, remove or disable its POL plugin entry, and launch again.

## Compatibility

When FFXI starts, LimitBreak looks for the part of the game responsible for creating this resource memory system. It then checks the surrounding code and memory relationships to make sure they match a layout LimitBreak understands.

If exactly one compatible layout is found, LimitBreak applies the change.

If the client is unfamiliar, ambiguous, or does not match the expected memory system, LimitBreak refuses to patch it.

That allows one `limitbreak.dll` to work across compatible FFXI client builds while still failing safely on clients it does not understand.

## What LimitBreak changes

LimitBreak makes a very small change during startup: it raises the value FFXI uses when creating its main resource pool.

- Stock FFXI resource pool: about **192 MB**
- LimitBreak resource pool: about **320 MB**

The neighboring resource pools keep their normal sizes. LimitBreak does not replace FFXI's allocator, move existing allocations, or modify `FFXiMain.dll` on disk.

After FFXI creates the pools, LimitBreak checks the resulting layout once to confirm that the expansion actually worked.

## Startup status

`/limitbreak status` writes the current status to Ashita's `logs/limitbreak` folder.

You may see these results:

| Result | Meaning |
| --- | --- |
| `CAPACITY_VERIFIED` | The expected 320 MB resource pool was created successfully. |
| `CAPACITY_FALLBACK` | FFXI could not create the larger allocation and used its built-in smaller fallback instead. |
| `CAPACITY_STRUCTURAL_FAILURE` | The resulting memory layout was not what LimitBreak expected. Restart without LimitBreak. |

Fallback and structural failures also produce an Ashita chat warning.

`PATCHED` by itself does not mean the final 320 MB layout was successfully created. `CAPACITY_VERIFIED` is the successful result.

## Safety and limitations

LimitBreak checks a number of things before it changes anything. Among other checks, it makes sure:

- it found one unambiguous FFXI memory layout that it understands
- the resource pools have not already been created
- the values it plans to change are still the expected stock values
- the discovered code has not changed between inspection and patching

After writing the change, LimitBreak verifies the result and restores the original memory protections. If a write fails, it attempts to restore the original bytes. If it cannot prove that restoration succeeded, it terminates the client rather than letting FFXI continue with partially modified code.

LimitBreak still lives inside a 32-bit game. The larger pool consumes additional virtual address space, and the pool can still eventually fill or become fragmented. Other plugins, wrappers, unusual client modifications, or unrelated FFXI bugs can still cause crashes.

The goal is practical stability with larger texture packs, not unlimited memory.

## Read-only discovery mode

For development or compatibility testing, using the POL argument `discover` runs the startup discovery process without patching FFXI.

This is mainly useful for testing whether an unfamiliar client has a memory layout LimitBreak understands.

## Building from source

LimitBreak is a 32-bit Windows C++ project.

Building requires:

- Visual Studio 2022 C++ Build Tools
- CMake 3.20+
- Python 3
- Ashita 4.30 SDK
- Capstone 5.0.9
- MinHook 1.3.4

```powershell
cmake -S . -B build -A Win32 -DASHITA_SDK="$PWD/deps/ashita-sdk" -DMINHOOK_SOURCE="$PWD/deps/minhook" -DCAPSTONE_SOURCE="$PWD/deps/capstone-5.0.9/src"
cmake --build build --config Release
```

For implementation and testing details, see:

- [Testing](TESTING.md)
- [Runtime discovery](docs/NATIVE_DISCOVERY.md)
- [Discovery tools](docs/DISCOVERY.md)

LimitBreak is released under the [GNU General Public License v3](LICENSE), matching SpectralFix's licensing approach. Third-party dependencies retain their own licenses.
