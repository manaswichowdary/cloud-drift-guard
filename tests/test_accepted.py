from datetime import date

import pytest

from scanner import accepted
from scanner.models import Finding


def f(rule, resource):
    return Finding(rule, "low", resource, "m", "fix")


ENTRIES = [{"rule_id": "S3-LOGGING", "resource": "sagemaker-us-*", "reason": "r", "review_by": "2027-02-10"}]


def test_matching_finding_is_accepted_and_others_stay_active():
    active, ok = accepted.split([f("S3-LOGGING", "sagemaker-us-east-1-1"), f("S3-LOGGING", "other"),
                                 f("S3-VERSIONING", "sagemaker-us-east-1-1")], ENTRIES, today=date(2026, 11, 10))
    assert [x.resource for x in ok] == ["sagemaker-us-east-1-1"]
    assert len(active) == 2


def test_acceptance_expires_after_review_date():
    active, ok = accepted.split([f("S3-LOGGING", "sagemaker-us-east-1-1")], ENTRIES, today=date(2027, 2, 11))
    assert ok == [] and len(active) == 1


def test_the_review_date_itself_still_counts():
    _, ok = accepted.split([f("S3-LOGGING", "sagemaker-us-east-1-1")], ENTRIES, today=date(2027, 2, 10))
    assert len(ok) == 1


def test_an_entry_without_a_reason_is_rejected(tmp_path):
    p = tmp_path / "a.json"
    p.write_text('[{"rule_id": "X", "resource": "y", "review_by": "2027-01-01"}]')
    with pytest.raises(ValueError, match="reason"):
        accepted.load(str(p))


def test_the_shipped_file_loads_and_every_entry_has_a_reason():
    entries = accepted.load()
    assert entries and all(e["reason"].strip() for e in entries)
