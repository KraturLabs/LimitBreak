# Changelog

## 1.0.1 - 2026-09-26

### Changed

- `/limitbreak status` now reports readable status in chat as well as the log,
  including whether the 320 MiB pool has actually been verified.
- Clarified that FFXI's allocation fallback is 64 MiB, below the stock 192 MiB pool.
- Limited patch writes and rollback to the two changed bytes while retaining
  full code validation, write verification and original page protections.
- Removed unused hashing code and the bcrypt build dependency.
- Named startup states and consolidated duplicate patch eligibility checks.

### Fixed

- Failed initialization now closes its log and releases prepared MinHook
  resources before hook activation. Module pinning happens after hook preparation.

### Compatibility

The 320 MiB target, startup POL plugin requirement, semantic compatibility checks,
read-only discovery mode and process-lifetime hook retention are unchanged.
Restart the game after replacing the DLL; live pool resizing is not supported.

## 1.0.0

- Initial public release for Ashita 4.30, expanding the main FFXI resource pool
  from approximately 192 MiB to 320 MiB on supported client layouts.
- Added semantic startup discovery, read-only `discover` mode, verified patch
  rollback and one-time capacity verification with fallback/failure warnings.
