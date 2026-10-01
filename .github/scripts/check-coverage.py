import json, sys
report = json.load(open(sys.argv[1]))
files = [f for data in report["data"] for f in data["files"]]
assert files, "coverage report contains no production files"
failed = False
for kind in ("lines", "branches"):
    count = sum(f["summary"][kind]["count"] for f in files)
    covered = sum(f["summary"][kind]["covered"] for f in files)
    print(f"{kind}: {covered}/{count}")
    if count == 0 or covered != count:
        failed = True
for f in files:
    for kind in ("lines", "branches"):
        value = f["summary"][kind]
        if value["covered"] != value["count"]:
            print(f["filename"], kind, value)
assert not failed, "reachable coverage is below 100%; add tests or document a justified exclusion"
