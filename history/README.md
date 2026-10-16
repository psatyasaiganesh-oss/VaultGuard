# VaultGuard project history

`VaultGuard.bundle` is a verified, self-contained Git bundle containing the extracted project implementation commit and the standalone preparation commit. Original commit authors, dates, and messages are retained in that extracted history; commit IDs change when source directories are moved to the root.

The destination GitHub repository's main branch contains its own initialization and the source import. The bundled commits are an archived history, not ancestors of that import. No unrelated SurgeGuard implementation is reachable from the bundled main branch.

Restore it locally from this directory:

```bash
git clone VaultGuard.bundle restored-VaultGuard
cd restored-VaultGuard
git log --oneline
```

The bundled snapshot predates the publication integration: its implementation and tests match the published project, while clone instructions, this history archive, and publication provenance can differ. The [extraction provenance](../docs/EXTRACTION.md) links the original source commits.
