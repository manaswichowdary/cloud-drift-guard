import requests

ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_LINES = 10


def format_slack(findings, waste_usd=0.0):
    """One short message. Alerts nobody reads are worse than none, so we cap the length."""
    if not findings:
        return None
    ordered = sorted(findings, key=lambda f: (ORDER.get(f.severity, 3), f.rule_id, f.resource))
    lines = [f"*{len(findings)} new finding(s)*" + (f", about ${waste_usd:.2f}/month of waste" if waste_usd else "")]
    for f in ordered[:MAX_LINES]:
        lines.append(f"• [{f.severity}] `{f.rule_id}` {f.resource}: {f.message} Fix: {f.fix}")
    if len(ordered) > MAX_LINES:
        lines.append(f"...and {len(ordered) - MAX_LINES} more in the findings table.")
    return {"text": "\n".join(lines)}


def send_slack(url, payload, post=requests.post):
    resp = post(url, json=payload, timeout=10)
    resp.raise_for_status()
