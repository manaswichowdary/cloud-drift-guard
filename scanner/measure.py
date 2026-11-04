"""Count how many planted mistakes a scan caught.

  terraform -chdir=terraform output -json planted > planted.json
  python -m scanner.cli scan --json findings.json
  python -m scanner.measure planted.json findings.json
"""
import json
import sys


def measure(planted, findings):
    """Return (caught, total, missed). `planted` is a list of {rule_id, resource}."""
    got = {(f["rule_id"], f["resource"]) for f in findings}
    want = [(p["rule_id"], p["resource"]) for p in planted]
    missed = [w for w in want if w not in got]
    return len(want) - len(missed), len(want), missed


def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) != 2:
        sys.exit("usage: python -m scanner.measure planted.json findings.json")
    planted = json.load(open(argv[0]))
    findings = json.load(open(argv[1]))
    caught, total, missed = measure(planted, findings)
    print(f"Caught {caught} of {total} planted mistakes.")
    for rule_id, resource in missed:
        print(f"  missed: {rule_id} on {resource}")
    return 0 if not missed else 1


if __name__ == "__main__":
    sys.exit(main())
