"""Findings we have looked at and decided to live with, each with a reason and a date to look again.

A finding is accepted when its rule_id matches and its resource matches the pattern (shell style, so
"sagemaker-us-*" works). After review_by the acceptance expires and the finding is reported again, so a decision
made today cannot hide a problem forever.
"""
import fnmatch
import json
import os
from datetime import date

DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accepted_risks.json")


def load(path=DEFAULT_FILE):
    with open(path) as fh:
        entries = json.load(fh)
    for e in entries:
        missing = {"rule_id", "resource", "reason", "review_by"} - set(e)
        if missing:
            raise ValueError(f"accepted risk {e} is missing {sorted(missing)}")
    return entries


def split(findings, entries, today=None):
    """Return (active, accepted). Only findings with a current, matching entry are accepted."""
    today = today or date.today()
    current = [e for e in entries if date.fromisoformat(e["review_by"]) >= today]
    active, accepted = [], []
    for f in findings:
        if any(e["rule_id"] == f.rule_id and fnmatch.fnmatch(f.resource, e["resource"]) for e in current):
            accepted.append(f)
        else:
            active.append(f)
    return active, accepted
