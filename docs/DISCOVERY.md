# Read-only developer tools

`tools/discover.py` derives the resource initializer, cap operands, pool globals
and allocator relationships using the same semantic schemas as the native DLL.
It reports JSON and never patches or creates a dump. A discovery result alone
is not permission to patch; the plugin also enforces startup timing and guards.

Install the Python decoder dependency:

```powershell
python -m pip install --target deps/discovery capstone==5.0.9
```

Choose one input (replace placeholders with your own input):

```text
python tools/discover.py --pid <process-id>
python tools/discover.py --capture <mapped-image.bin> --base <loaded-base>
python tools/discover.py --dump <existing-full-minidump>
python tools/discover.py --file <FFXiMain.dll>
```

Live access requires 64-bit Windows Python and query/read permission for the
chosen process. Exactly one loaded FFXiMain.dll is required. The reader never
launches, connects, injects, suspends, executes code or writes target memory.
Mapped images require their actual load base. The dump reader derives it from
the module list and reads required image ranges from Memory64 streams. On-disk
packed/unbacked code can refuse; use an already mapped image in that case.

Exit 0 means one validated result; exit 2 means refusal. Output includes derived
addresses, layout, checks and provenance supplied by the input, not fixed client
identifiers. No output artifact is written automatically. Preserve confidentiality
when sharing reports: runtime process IDs, module paths and input digests can
appear in generated output. Do not commit captures or dumps.

## Generic validation helpers

`occupancy.observe(read, head, end)` accepts a caller-supplied read function and
validated stock or target arena bounds. It makes two bounded physical-chain walks
and checks reverse-free-list agreement, accounting and largest free block.
Rejected walks are missing observations, not zero usage. Matching walks are
consistency evidence, not an atomic snapshot or proof of corruption-free memory.
The helper does not attach to a client or discover addresses itself.

`BoundaryWatcher.check(snapshot)` checks five pool bounds, sibling spacing,
committed private read/write backing coverage and changes from the first valid
snapshot. Input has `pool_capacity_mib`, five `pools` entries with `head`/`end`,
and `backing_regions` entries with `base`, `size`, `state`, `protect`, `type`.
It reports violations; it never repairs memory or polls a process. Neither
helper changes the DLL's one-time verification policy. Tests supply synthetic
readers and snapshots; integrations must validate their own input source.
