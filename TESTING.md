# Validation

## Automated suite

Build using README.md, install the Python decoder, then run from the repository
root with 64-bit Windows Python:

```powershell
python -m pip install --target deps/discovery capstone==5.0.9
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python -m unittest discover -s tests -p "test_*.py" -v
```

Native tests cover cap arithmetic, five-pool classification, 64 MiB fallback,
retired target rejection, patch refusals, byte/protection preservation, hook
passthrough and POL exports. The startup suite exercises the actual callback
with a fake chat manager, including one-time warnings and unreadable layouts.
Python synthetic tests cover discovery policy, prefilter/schema agreement,
allocator accounting, changing reads and boundary validation. The normal CMake
build also assembles a synthetic PE using Visual Studio MASM. It is read only as
data, never loaded or executed, and requires no game capture. Its fixed assembly
contract is not generated from production rules during builds. Seventeen portable
graph mutations exercise full discovery and native/Python agreement; native
accepted/refused cases also pass through the actual patch gate on disposable
memory. Missing this built fixture fails the complete suite rather than skipping.

## Optional image integration

Regression mutations and native/Python parity accept caller-supplied inputs.
No game image is bundled or obtained automatically. To enable these suites set:

```powershell
$env:LIMITBREAK_TEST_CAPTURE = '<mapped-image.bin>'
$env:LIMITBREAK_TEST_BASE = '<actual-loaded-base>'
$env:LIMITBREAK_TEST_DUMP = '<existing-full-minidump>'
python -m unittest discover -s tests -p "test_*.py" -v
```

Capture and base are a pair; the dump is independently optional. Use a complete
stock 192 MiB mapped image with a uniquely supported graph and executable space
for relocation mutations. Tests derive addresses from that input; there are no
client-specific address or hash oracles. Mutations run on disposable copies,
never on the input or a live process. The native checker also verifies that
refused patches leave bytes unchanged and accepted startup copies change only
the two derived operands. Missing optional inputs or a missing native checker
are explicit skips, not passes. An invalid supplied input is a test failure.

## Manual startup validation

1. Close the client and install/configure the built DLL as described in README.md.
2. Launch normally. Check for normal startup and absence of LimitBreak errors.
3. Require `CAPACITY_VERIFIED`, not merely `PATCHED`. If independent confirmation
   is needed, run the existing read-only discovery tool against that process and
   compare all five budgets, alignment and sibling order.
4. Confirm fallback and structural failures are reported accurately if those
   conditions occur. Do not force dangerous allocation failures in ordinary use.
5. To validate rollback to stock, exit fully, disable the POL entry and restart.

Use the same built DLL when comparing supported environments. Broader gameplay,
retention or load testing is separate from startup acceptance. Automated checks
and one startup do not prove universal compatibility, leak freedom, GPU safety
or every OS failure path. Never shrink a live arena.

## Test-portability coverage audit

A configured clean checkout needs the documented public build dependencies but
no game data. The optional tests remain optional; portable coverage supplements
them rather than relabeling skips as passes.

| Optional group | Tests | Input | Additional confidence |
| --- | ---: | --- | --- |
| `CaptureTests` | 17 | Mapped image and actual load base | Full discovery/mutations against real compiled instruction and PE layouts. |
| `NativeMutationTests` | 17 | Same image/base plus built native checker | Native/Python agreement and actual discovery-to-patch byte invariants on real compiled layouts. |
| `DumpIntegrationTests` | 1 | Existing complete dump | Module/Memory64 parsing and discovery through real dump ranges. |
| `NativeDumpTests` | 1 | Same dump plus native checker | Native/Python discovery agreement on the image reconstructed from the dump. |

The mapped-image mutations cover baseline address relationships, changed hash,
rebasing, moved globals/initializer, selector routing, missing candidate/import,
retired/mismatched caps and layouts, partial globals, each wrapper reference,
initializer branches, allocator/builder/backing tampering, duplicate candidates,
and missing/changing reads. Inherited rebase and missing/changing-reader tests
exercise Python only, even in the native-named suite; other cases invoke the
native checker. Portable tests preserve this distinction.

| Production behavior | Capture-free automated coverage | Limit |
| --- | --- | --- |
| Full semantic discovery and ambiguity/refusal | Synthetic PE and graph mutations invoke production discovery; duplicate valid candidates, missing/tampered relationships and moved addresses are checked. | One fixed synthetic graph is not real-build compatibility proof. |
| Derived patch targeting and startup eligibility | Native patch-gate tests and synthetic discovery-to-patch integration verify only derived operands change; wrong caller, late globals, low memory, invalid/ambiguous discovery and byte drift refuse. | OS callback timing and loaded-module ownership are not end-to-end simulated. |
| 320 MiB layout and 64 MiB fallback | Native layout tests and actual present-callback tests cover all five spans, alignment, ordering, overflow, mixed/stock/retired layouts, unreadability and one-time warnings. | Does not induce a real backing-allocation failure or verify visible chat in a client. |
| Write/protection safeguards | Real disposable pages test checked writes, non-mutating refusals, repeated patch refusal and independent cross-region protection restoration. | Failed/partial OS writes, cache-flush failures, rollback execution/failure and fatal termination are not fault-injected in either optional or portable tests. |
| Startup policy and passthrough | Argument policy, prefilter/schema agreement, patch eligibility and one-shot callback behavior have portable tests; a real memory-query hook smoke test checks passthrough. | Full plugin initialization, owner-module guard, missed-query timing, module pinning and shutdown lifecycle lack complete end-to-end automated coverage. |

Thus the suite has meaningful portable coverage of the core discovery/patch/layout
contracts, but does not establish every production-critical failure or lifecycle
path. The rollback/lifecycle gaps are not private-fixture dependencies and were
not expanded as part of this portability-only change. No runtime modification or
live test is needed to run these tests.
