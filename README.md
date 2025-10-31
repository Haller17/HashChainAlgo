# Tamper-Evident Audit Logger (Hash Chain)

A Python project library that writes **append-only, tamper-evident** audit logs.  
Each entry includes the SHA-256 hash of the **previous** entry and of the **current** payload, forming a verifiable hash chain. Any change to history breaks verification.

---

## How It Works
- Every log entry includes:
  - `prev_hash`: the last entry’s `hash` (or `"GENESIS"` for the first)
  - `hash`: `SHA256( json.dumps({ prev: prev_hash, payload }, sort_keys=True) )`
- `sort_keys=True` ensures **stable serialization**, so the same inputs always produce the same bytes and the same hash.
- `verify()` recomputes expected hashes in sequence and returns **True/False**.

---
