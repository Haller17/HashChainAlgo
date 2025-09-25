from hashchain_log import HashChainLogger

log = HashChainLogger()

log.append("test", "start", {"step": 1})
log.append("test", "continue", {"step": 2})
log.append("test", "end", {"ok": True})

print("Valid chain?", HashChainLogger().verify())  # should print True
