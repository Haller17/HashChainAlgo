import os, json, time, hashlib
from dataclasses import dataclass, asdict
from typing import Optional

LOG_PATH = "security_audit.log"


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _line_hash(prev_hash: str, payload: dict) -> str:
    body = json.dumps({"prev": prev_hash, "payload": payload}, sort_keys=True).encode()
    return _sha256(body)


@dataclass
class AuditEntry:
    ts: float
    actor: str
    action: str
    details: dict
    prev_hash: str
    hash: str


class HashChainLogger:
    def __init__(self, path: str = LOG_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        self._last_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return "GENESIS"
        with open(self.path, "r", encoding="utf-8") as f:
            last = f.readlines()[-1].strip()
        try:
            rec = json.loads(last)
            return rec["hash"]
        except Exception:
            return "GENESIS"

    def append(self, actor: str, action: str, details: Optional[dict] = None) -> AuditEntry:
        details = details or {}
        payload = {"ts": time.time(), "actor": actor, "action": action, "details": details}
        h = _line_hash(self._last_hash, payload)
        entry = AuditEntry(ts=payload["ts"], actor=actor, action=action,
                           details=details, prev_hash=self._last_hash, hash=h)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
        self._last_hash = h
        return entry

    def verify(self) -> bool:
        prev = "GENESIS"
        if not os.path.exists(self.path):
            return True
        with open(self.path, "r", encoding="utf-8") as f:
            for raw in f:
                rec = json.loads(raw.strip())
                payload = {"ts": rec["ts"], "actor": rec["actor"],
                           "action": rec["action"], "details": rec["details"]}
                expect = _line_hash(prev, payload)
                if rec.get("hash") != expect or rec.get("prev_hash") != prev:
                    return False
                prev = rec["hash"]
        return True
