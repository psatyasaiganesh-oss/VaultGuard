# VaultGuard interview walkthrough

## 60-second opening

“VaultGuard is an independent Python backup-integrity lab inspired by Rubrik’s published discussion of immutable backups, layered checksums, background scans, rebuilds, and restore validation. The business risk is that a backup can report success but be corrupt or ransomware-damaged when recovery starts. My implementation stores fixed-size chunks by SHA-256, deduplicates them across immutable snapshot manifests, writes a full local mirror, and verifies every manifest, chunk, and reconstructed file before restore. The demo corrupts six chunks, detects and repairs all six, restores 97 files exactly, enforces retention, and validates a tamper-evident audit chain.”

## Six-minute flow

### 1. Start with the failure, not the features

A successful write is not proof of recoverability. Three independent failures matter:

1. ransomware or an operator deletes a recovery point;
2. bit rot or partial writes silently change stored bytes;
3. metadata still looks healthy, but reconstruction or restore fails.

Rubrik’s public engineering material motivates append-only backup state, multiple integrity layers, background verification, resilient rebuilds, and automated restore tests. VaultGuard converts those properties into a locally reproducible exercise.

### 2. Follow a backup

`backup()` validates that source and repository do not overlap and rejects links/special files. For each regular file it opens with `O_NOFOLLOW`, reads 4 KiB chunks, hashes each chunk, and atomically writes absent content to primary and mirror paths. It checks inode, device, size, and mtime before/after reading to catch a concurrent change.

The canonical manifest stores file order, modes, mtimes, file hashes, and ordered chunk hashes. A Merkle root binds all file records, SHA-256 binds the full manifest, and the first 128 digest bits become the snapshot ID. SQLite commits the snapshot, chunk reference counts, and audit event in one metadata transaction.

### 3. Follow a failure and repair

`verify_snapshot()` validates the manifest schema, recomputes its digest and Merkle root, then hashes every primary chunk. It does not treat the mirror as correct merely because it exists: a repair is allowed only when the mirror’s expected size and SHA-256 match. Replacement uses a temporary file, `fsync`, atomic rename, and directory `fsync`. Finally it reconstructs each file hash from the repaired primary chunks.

If both copies are corrupt, verification fails and restore remains blocked. That behavior is intentional: availability must not silently override integrity.

### 4. Explain the restore boundary

Restore is a two-phase gate: full verification first, materialization second. Manifest paths must be canonical relative POSIX paths. Traversal, absolute paths, backslashes, source symlinks, destination symlinks, and overwrites are rejected. Each output file is created exclusively and hashed again while written, reducing the chance that corruption between verify and restore is accepted.

### 5. Show measured evidence

The committed deterministic run produced two 3 MiB snapshots. Heavy synthetic repetition reduced 6,291,456 logical bytes to 458,752 unique primary bytes (92.71% avoided before mirroring). It injected six primary corruptions and detected/repaired all six. The restored 97-file, 3,145,728-byte tree matched the source fingerprint, early deletion was rejected, the audit chain verified, and all 50 tests passed.

State the caveat: this is evidence about one synthetic local run—not a production performance claim.

### 6. Close with production evolution

The next production steps would be content-defined chunking, object-lock storage in separate failure domains, encryption with managed keys, signed/external audit checkpoints, application-consistent snapshots, idempotent workers, leases and mark-and-sweep GC, erasure coding, metrics/alerts, and regular isolated restore drills.

## Questions to expect

### Why both file hashes and chunk hashes?

Chunk hashes locate and repair the smallest damaged unit. A whole-file hash also binds chunk order and catches reconstruction errors. The manifest digest and Merkle root protect metadata structure at different granularities.

### Why is the retention lock not truly immutable?

The Python service rejects deletion before the deadline, but a local administrator can bypass it and modify storage directly. A real immutability boundary needs independently enforced WORM/object lock or a storage layer that clients cannot rewrite.

### Why use a full mirror instead of erasure coding?

It keeps the project understandable and makes repair behavior directly testable. The cost is 100% redundancy and a shared host failure domain. Erasure coding offers better space efficiency but adds shard placement, quorum, reconstruction, and correlated-failure concerns.

### What happens if the process crashes halfway through backup?

Metadata is transactional, so a partial snapshot is not visible. Atomic chunk writes prevent partial files at final names. A crash can leave valid unreferenced chunks or a manifest; a production implementation needs startup reconciliation and safe mark-and-sweep garbage collection.

### Can SHA-256 collisions corrupt data?

The implementation assumes SHA-256 collision resistance, a normal content-addressing tradeoff. It still validates length and digest on reads. A production format should version the hash algorithm so it can migrate later.

### How would you make scrub efficient at scale?

Track last-verified time and storage generation per chunk, schedule scans by risk and age, cap I/O, verify unique chunks once, persist idempotent repair tasks, expose corruption/repair metrics, and run restore drills on sampled recovery points.

## Evidence-based resume bullets

- Built **VaultGuard**, a standard-library Python snapshot engine with SHA-256 content addressing, Merkle-bound manifests, transactional SQLite metadata, retention enforcement, safe verify-before-restore, and hash-chained audit records; covered behavior with **50 passing unit/integration tests** and a non-root Docker/CI workflow.
- Created a deterministic corruption lab that stored **6,291,456 logical bytes in 458,752 unique primary bytes (92.71% synthetic deduplication)**, detected and mirror-repaired **6/6 injected chunk faults**, and restored **97 files / 3,145,728 bytes** with an exact tree-fingerprint match.

## Accuracy statement

Say “inspired by Rubrik’s public engineering material.” Do not say this is Rubrik architecture, a Rubrik clone, production ransomware protection, or work completed for Rubrik. The chosen algorithms, code, tests, and measurements are independent.
