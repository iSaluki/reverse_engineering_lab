# Deliberately vulnerable fixture for tests/smoke.sh (vuln-scan semgrep rules). Not real code.
import os, pickle, requests, subprocess, tarfile, yaml
def sync(host, blob, path, db=None):
    obj = pickle.loads(blob)
    cfg = yaml.load(open(path))
    safe = yaml.load(open(path), Loader=yaml.SafeLoader)   # must NOT match
    os.system("ping -c1 " + host)
    os.system("true")                                      # must NOT match
    requests.get("https://api.example.com/sync", verify=False)
    tarfile.open(path).extractall("/tmp/x")
    eval(host)
    eval("1+1")                                            # must NOT match
    db.execute("SELECT * FROM t WHERE h='%s'" % host)
    return obj, cfg, safe
