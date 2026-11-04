from scanner.rules import ALL_RULES


def run_all(session, rules=ALL_RULES):
    """Run every rule. One broken rule must not hide the others, so errors are collected."""
    findings, errors = [], []
    for rule in rules:
        try:
            findings.extend(rule(session))
        except Exception as e:  # noqa: BLE001  a rule can fail on permissions, we report it
            errors.append({"rule": rule.__name__, "error": f"{type(e).__name__}: {e}"})
    return findings, errors
