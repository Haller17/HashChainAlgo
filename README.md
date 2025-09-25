# HashChainAlgo
A small, dependency-free Python module that adds tamper-evident, hash-chained logs to your app. Each event is written as one JSON line that cryptographically links to the previous one. If any past line changes, verification fails.

Why this exists

Integrity & forensics: prove runs weren’t altered after the fact.

Lightweight: pure stdlib; drop-in to any Python project.

Human-readable: newline-delimited JSON (one record per line).

Quick start
from hashchain_log import HashChainLogger

log = HashChainLogger(path="logs/security_audit.log")
log.append("app", "start_simulation", {"file": "net1.txt", "mode": "vanilla"})
# … do work …
log.append("app", "simulation_complete", {"matrix": "interaction_matrix.png"})
print("Valid chain?", log.verify())  # -> True

File layout

hashchain_log.py — the logger module (production code)

demo_hashchain.py (optional) — minimal demo: valid → tamper → invalid

verify_logs.py (optional) — one-shot integrity check CLI

Code walkthrough (what each block does)
Imports & default path
import os, json, time, hashlib
from dataclasses import dataclass, asdict
from typing import Optional

LOG_PATH = "security_audit.log"


Standard library only.

LOG_PATH is the default logfile if you don’t pass one.

SHA-256 helper
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


Returns a 64-char lowercase SHA-256 hex digest for the given bytes.

Compute the chained hash for one entry
def _compute_line_hash(prev_hash: str, payload: dict) -> str:
    serialized = json.dumps({"prev": prev_hash, "payload": payload}, sort_keys=True).encode()
    return _sha256_hex(serialized)


Canonicalizes {prev, payload} with sorted keys, encodes to bytes, hashes it.

Output depends on both the previous hash and this entry’s payload → tamper-evident chaining.

Log record model
@dataclass
class AuditEntry:
    ts: float        # timestamp (epoch seconds)
    actor: str       # who wrote it (e.g., "app")
    action: str      # what happened (e.g., "start_simulation")
    details: dict    # free-form metadata, JSON-serializable
    prev_hash: str   # previous entry's hash or "GENESIS"
    hash: str        # this entry’s chained SHA-256 hash


Lightweight, serializable container for a single line in the log.

Logger: constructor
class HashChainLogger:
    def __init__(self, path: str = LOG_PATH):
        self.log_path = path
        log_dir = os.path.dirname(path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        self._last_hash = self._read_tail_hash()


Stores the log path, creates its directory if needed, and loads the last hash from the file (or "GENESIS" if empty) so the next write links correctly.

Load the last hash from the file
def _read_tail_hash(self) -> str:
    if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
        return "GENESIS"
    with open(self.log_path, "r", encoding="utf-8") as fh:
        last_line = fh.readlines()[-1].strip()
    try:
        record = json.loads(last_line)
        return record["hash"]
    except Exception:
        return "GENESIS"


Reads the final line, parses it, and returns its hash.

Falls back to "GENESIS" on missing/empty/corrupt files.

Append a chained entry
def append(self, actor: str, action: str, details: Optional[dict] = None) -> AuditEntry:
    details = details or {}
    entry_payload = {"ts": time.time(), "actor": actor, "action": action, "details": details}
    entry_hash = _compute_line_hash(self._last_hash, entry_payload)

    entry_obj = AuditEntry(
        ts=entry_payload["ts"], actor=actor, action=action,
        details=details, prev_hash=self._last_hash, hash=entry_hash,
    )

    with open(self.log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(entry_obj)) + "\n")

    self._last_hash = entry_hash
    return entry_obj


Builds the payload, computes its chained hash, writes a JSON line, and updates the in-memory tail hash.

Verify the whole file
def verify(self) -> bool:
    chain_prev = "GENESIS"
    if not os.path.exists(self.log_path):
        return True

    with open(self.log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            record = json.loads(line.strip())
            entry_payload = {
                "ts": record["ts"], "actor": record["actor"],
                "action": record["action"], "details": record["details"],
            }
            expected_hash = _compute_line_hash(chain_prev, entry_payload)

            if record.get("hash") != expected_hash or record.get("prev_hash") != chain_prev:
                return False
            chain_prev = record["hash"]

    return True


Replays the chain from the top: recomputes each hash and checks the link (prev_hash).

Returns False if any line was edited, deleted, or re-ordered; True only if the chain is intact.
