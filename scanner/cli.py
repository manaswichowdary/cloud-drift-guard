"""Command line entry point.

  python -m scanner.cli scan   [--endpoint-url URL] [--db findings.db] [--slack]
  python -m scanner.cli drift  --state state.json [--endpoint-url URL]
  python -m scanner.cli cost
  python -m scanner.cli fix-pr --repo owner/name [--open]   (dry run unless --open)
"""
import argparse
import json
import os
import subprocess
import sys

import boto3

from scanner import alerts, cost, drift, fixes, github_pr
from scanner.runner import run_all
from scanner.store import Store


def _session(args):
    if args.endpoint_url:
        # boto3 reads this variable, so every client in every rule talks to the fake AWS.
        os.environ["AWS_ENDPOINT_URL"] = args.endpoint_url
    return boto3.Session(region_name=args.region)


def _print(findings, errors):
    for f in sorted(findings, key=lambda x: (alerts.ORDER.get(x.severity, 3), x.rule_id, x.resource)):
        print(f"[{f.severity:6}] {f.rule_id:20} {f.resource}\n         {f.message}\n         Fix: {f.fix}")
    for e in errors:
        print(f"[error ] {e['rule']}: {e['error']}")
    print(f"\n{len(findings)} finding(s), {len(errors)} rule error(s), "
          f"about ${cost.monthly_waste(findings):.2f}/month of waste flagged.")


def _alert(args, store, findings, kinds):
    new, resolved = store.record(findings, kinds=kinds)
    payload = alerts.format_slack(new, cost.monthly_waste(new))
    print(f"{len(new)} new, {len(resolved)} resolved since the last scan.")
    if payload and args.slack:
        url = os.environ.get("SLACK_WEBHOOK_URL")
        if not url:
            sys.exit("Set SLACK_WEBHOOK_URL to send alerts.")
        alerts.send_slack(url, payload)
        print("Alert sent.")
    return new


def cmd_scan(args):
    session = _session(args)
    findings, errors = run_all(session)
    _print(findings, errors)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)
    _alert(args, Store(args.db), findings, kinds={"security", "waste"})
    return 1 if any(f.severity == "high" for f in findings) and args.fail_on_high else 0


def cmd_drift(args):
    session = _session(args)
    if args.state:
        state = json.load(open(args.state))
    else:
        out = subprocess.run(["terraform", "show", "-json"], cwd=args.tf_dir, capture_output=True, text=True, check=True)
        state = json.loads(out.stdout)
    findings = drift.check_drift(session, state)
    _print(findings, [])
    _alert(args, Store(args.db), findings, kinds={"drift"})
    return 0


def cmd_cost(args):
    session = _session(args)
    finding = cost.spend_jump(cost.fetch_daily_costs(session))
    print(finding.message if finding else "No unusual spend jump.")
    return 0


def cmd_fix_pr(args):
    session = _session(args)
    findings, _ = run_all(session)
    files, fixed = {}, []
    for f in findings:
        proposal = fixes.propose(f)
        if proposal:
            files.update(proposal)
            fixed.append(f)
    if not files:
        print("Nothing safe to fix automatically.")
        return 0
    for path in files:
        print("would add", path)
    if not args.open:
        print("Dry run. Add --open to create the pull request.")
        return 0
    token = os.environ.get("GITHUB_TOKEN") or sys.exit("Set GITHUB_TOKEN to open a pull request.")
    body = "These fixes only add protection (versioning, public access block, a password policy).\n\n" + \
        "\n".join(f"- {f.rule_id} {f.resource}: {f.message}" for f in fixed)
    print(github_pr.open_fix_pr(token, args.repo, args.base, args.branch, files,
                                "Fix safe findings from Cloud Drift Guard", body))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="scanner")
    p.add_argument("--endpoint-url", default=None, help="Use a fake AWS such as moto server, for example http://localhost:4566")
    p.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    p.add_argument("--db", default="findings.db")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("--json"); s.add_argument("--slack", action="store_true")
    s.add_argument("--fail-on-high", action="store_true"); s.set_defaults(fn=cmd_scan)
    d = sub.add_parser("drift"); d.add_argument("--state"); d.add_argument("--tf-dir", default="terraform")
    d.add_argument("--slack", action="store_true"); d.set_defaults(fn=cmd_drift)
    c = sub.add_parser("cost"); c.set_defaults(fn=cmd_cost)
    f = sub.add_parser("fix-pr"); f.add_argument("--repo", required=True); f.add_argument("--base", default="main")
    f.add_argument("--branch", default="drift-guard-fixes"); f.add_argument("--open", action="store_true")
    f.set_defaults(fn=cmd_fix_pr)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
