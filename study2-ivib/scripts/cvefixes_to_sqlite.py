#!/usr/bin/env python3
"""Load the CVEfixes SQL dump (gzip) into SQLite, the way INSTALL.md does with the sqlite3 CLI (not
installed here). Statements are accumulated until sqlite3.complete_statement() says they are whole.
Writes to <db>.tmp and renames at the end, so a reboot mid-way simply starts the load again.
usage: cvefixes_to_sqlite.py dump.sql.gz out.db
"""
import gzip
import os
import sqlite3
import sys
import time

src, dst = sys.argv[1], sys.argv[2]
tmp = dst + ".tmp"
if os.path.exists(tmp):
    os.remove(tmp)
con = sqlite3.connect(tmp, isolation_level=None)
con.execute("PRAGMA journal_mode=OFF")
con.execute("PRAGMA synchronous=OFF")
con.execute("BEGIN")
buf, n, t0 = [], 0, time.time()
with gzip.open(src, "rt", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        buf.append(line)
        if line.rstrip().endswith(";") and sqlite3.complete_statement("".join(buf)):
            stmt = "".join(buf)
            buf = []
            s = stmt.lstrip()[:20].upper()
            if s.startswith(("BEGIN", "COMMIT", "PRAGMA")):
                continue
            con.execute(stmt)
            n += 1
            if n % 200000 == 0:
                print(f"{n} statements {time.time() - t0:.0f}s", flush=True)
con.execute("COMMIT")
for idx in ("CREATE INDEX IF NOT EXISTS fc_hash ON file_change(hash)",
            "CREATE INDEX IF NOT EXISTS fc_id ON file_change(file_change_id)",
            "CREATE INDEX IF NOT EXISTS mc_fc ON method_change(file_change_id)",
            "CREATE INDEX IF NOT EXISTS fx_hash ON fixes(hash)",
            "CREATE INDEX IF NOT EXISTS cc_cve ON cwe_classification(cve_id)"):
    con.execute(idx)
con.close()
os.replace(tmp, dst)
print(f"done: {n} statements -> {dst}")
