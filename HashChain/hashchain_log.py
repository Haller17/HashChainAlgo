#Andrew Haller
#Andrew16haller@gmail.com
import os, json, time, hashlib
from dataclasses import dataclass, asdict
from typing import Optional

LOG_PATH = "security_audit.log"


def _SHA_hex(data: bytes) -> str: #Returns hex number into String
    return hashlib.sha256(data).hexdigest()

#Creates a JSON object that contains the previous entry's hash and the current entry hash
#Sort_keys=True: makes the key order the same, so inputs always produce the same bytes
#Returns the given string from the prev and current. If either changes later, the hash wont match, and will output false
def _compute_line_hash(prev_hash: str, payload: dict) -> str:
    serialized = json.dumps({"prev": prev_hash, "payload": payload}, sort_keys=True).encode()
    return _SHA_hex(serialized)


@dataclass
class AuditEntry:
    ts: float #Timestamp
    actor: str #Who wrote the entry
    action: str #What happend
    details: dict #metadata
    prev_hash: str #Prev Hash
    hash: str #Current hash after going under SHA

#This class logs and writes tamper evident entries. Every new entry links to the prev one, so any edits will be detected
class HashChainLogger:
    #Sets up the logger so each write in, will chain to the last file that was entered
    def __init__(self, path: str = LOG_PATH):
        self.log_path = path
        log_dir = os.path.dirname(path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        self._last_hash = self._read_tail_hash() #Loads prev hash. Sets up the chain so the next append will link it

#Takes the most recent hash of the prev entry, and chains it
    def _read_tail_hash(self) -> str:
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return "GENESIS"
        #Open the log, take the last line
        with open(self.log_path, "r", encoding="utf-8") as fh:
            last_line = fh.readlines()[-1].strip() #removes whitespace or newline
        try:
            #Parse the last line, and return the hash from the entry
            record = json.loads(last_line)
            return record["hash"] #New chain tail
        #Throw an exception if the parsing fails
        except Exception:
            return "GENESIS"

#Method to add a new log entry. Takes in who did it, what happened, and metadata
    def append(self, actor: str, action: str, details: Optional[dict] = None) -> AuditEntry:
        details = details or {} #If no detials, then make it empty
        entry_payload = {
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "details": details,
        }
        #Computes the chained hash to this entry hashing. Links the new with the prev one
        entry_hash = _compute_line_hash(self._last_hash, entry_payload)

        #Dataclass instance to represent the log record
        entry_obj = AuditEntry(
            ts=entry_payload["ts"],
            actor=actor,
            action=action,
            details=details,
            prev_hash=self._last_hash,
            hash=entry_hash,
        )

        #Opens the log file, writes the entry as a JSON line
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry_obj)) + "\n")

        #Updates the tail of the chain, and returns the new object
        self._last_hash = entry_hash
        return entry_obj

    #This checks the enire log file. Returns true if not tampered with. Else, false
    def verify(self) -> bool:
        chain_prev = "GENESIS" #Prev hash links to
        if not os.path.exists(self.log_path):
            return True #if no file to start with, its true
        #opens the log to check, iterates through each log entry
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                record = json.loads(line.strip())
                entry_payload = {
                    "ts": record["ts"],
                    "actor": record["actor"],
                    "action": record["action"],
                    "details": record["details"],
                }
                #Compute what the entry's hash should be
                expected_hash = _compute_line_hash(chain_prev, entry_payload)

                #The stored hash must mtach re-computed expected hash = True
                #The stored Prev Hash must match the Chain Prev = True.
                #If either fails, then return flase. Something was tampered with
                if record.get("hash") != expected_hash or record.get("prev_hash") != chain_prev:
                    return False

                chain_prev = record["hash"]

        return True


