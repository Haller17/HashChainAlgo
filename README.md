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

## Example Usage

```python
from audit_logger import HashChainLogger  # rename to your module name

# Optional: choose a log file path (default: security_audit.log)
logger = HashChainLogger(path="security_audit.log")

# Write entries
logger.append(actor="service/api", action="LOGIN_SUCCESS", details={"user_id": "123"})
logger.append(actor="service/db",  action="UPDATE",         details={"table": "orders", "id": 42})

# Verify the entire log
ok = logger.verify()
print("Chain valid?", ok)
