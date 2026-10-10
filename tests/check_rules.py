"""Assert the semgrep rules behave on tests/fixtures: every rule id fires at least once, and no line marked
'must NOT match' is reported. usage: check_rules.py <semgrep.json>   (from: vuln-scan tests/fixtures -o OUT)"""
import glob
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
d = json.load(open(sys.argv[1]))
hits = {r["check_id"].split(".")[-1] for r in d["results"]}
ids = set()
for f in glob.glob(os.path.join(REPO, "rules", "semgrep", "*.yml")):
    ids |= set(re.findall(r"^  - id: (\S+)", open(f).read(), re.M))
neg = set()
for f in glob.glob(os.path.join(REPO, "tests", "fixtures", "**", "*.*"), recursive=True):
    for i, line in enumerate(open(f, encoding="utf-8"), 1):
        if "must NOT match" in line:
            neg.add((os.path.basename(f), i))
fps = [(r["path"], r["start"]["line"], r["check_id"].split(".")[-1]) for r in d["results"]
       if (os.path.basename(r["path"]), r["start"]["line"]) in neg]
missing = sorted(ids - hits)
print(f"rules {len(ids)}, firing {len(ids & hits)}, missing {missing}, false positives {fps}, errors {len(d['errors'])}")
sys.exit(1 if missing or fps or d["errors"] else 0)
