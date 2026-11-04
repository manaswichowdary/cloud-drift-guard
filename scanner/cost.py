from datetime import date, timedelta
from scanner.models import Finding


def fetch_daily_costs(session, days=21, today=None):
    """Daily unblended cost from Cost Explorer, oldest first. Each real call costs about one cent."""
    ce = session.client("ce", region_name="us-east-1")
    today = today or date.today()
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": (today - timedelta(days=days)).isoformat(), "End": today.isoformat()},
        Granularity="DAILY", Metrics=["UnblendedCost"])
    return [float(d["Total"]["UnblendedCost"]["Amount"]) for d in resp["ResultsByTime"]]


def spend_jump(daily_costs, window=7, factor=1.5, min_daily_usd=1.0):
    """Compare the last `window` days with the `window` days before. Returns a Finding or None.

    The floor keeps a jump from $0.02 to $0.05 a day from paging anyone.
    """
    if len(daily_costs) < window * 2:
        return None
    recent = sum(daily_costs[-window:]) / window
    before = sum(daily_costs[-2 * window:-window]) / window
    if recent < min_daily_usd:
        return None
    if before == 0 or recent / before >= factor:
        ratio = "from nothing" if before == 0 else f"{recent / before:.1f}x"
        return Finding("COST-JUMP", "medium", "account",
                       f"Daily spend is ${recent:.2f} over the last {window} days, up {ratio} from ${before:.2f}.",
                       "Open Cost Explorer, group by service, and find what changed.", kind="waste")
    return None


def monthly_waste(findings):
    """Total of the rough monthly waste across waste findings."""
    return round(sum(f.monthly_usd for f in findings if f.kind == "waste"), 2)
