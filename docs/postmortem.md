# Postmortem: security group opened to the whole internet (simulated)

This was a planned test on a demo security group in a real AWS account. Nothing was attached to the group and no real
data was at risk. I treated it like a real incident to check that the alert, runbook and fix work together.

## Summary

On Nov 4, 2026 at 17:46:08 a rule allowing all traffic from 0.0.0.0/0 was added by hand to the demo security group
`drift-demo-good-sg`. Cloud Drift Guard found it in the next scan and sent a high severity Slack alert in the same
minute. I put the group back to its Terraform definition at 17:48:34, and the following scan confirmed it was fixed.
The group was open for about 2 minutes and 26 seconds.

## Timeline (all times MST)

| Time | Event |
|---|---|
| 17:46:08 | Rule added through the AWS API (stands in for a rushed manual change) |
| 17:46:18 | Scan round started and found the new rule |
| 17:46 | Slack alert `SG-ALL-OPEN`, high severity, with the fix hint |
| 17:48:34 | Fixed with `terraform apply`, following the runbook |
| 17:48:48 | Next scan: 2 findings resolved (this rule and an earlier SSH rule on the same group) |

## Detection

A scan takes about 25 seconds and the timer waited 60 seconds between scans, so the worst case from change to alert
was about 85 seconds. This test happened to be caught 10 seconds after the change, so it was lucky timing and not the
typical case. The scans ran from a timer on my laptop. The same scan is set up as a GitHub Actions schedule every 5
minutes, but GitHub had not started its first scheduled run after more than 30 minutes, so that part is not yet
proven.

## Root cause

A change was made outside Terraform. Terraform's code said the group should allow HTTPS only, and nothing stopped
someone from editing the live group by hand.

## What went well

- The alert named the rule, the resource and a fix, so no one had to dig for context.
- Only the new finding was sent. The repeat scans before and after stayed quiet.
- The runbook gave a clear first step (`terraform apply` to put it back), and it worked the first time.

## What did not go well

- The account has no CloudTrail trail, which the scanner itself flags as `ACCT-NO-CLOUDTRAIL`. That means the runbook
  step "check who made the change" cannot be done in this account.
- The scanner finds that a rule is open, but it does not say who opened it.

## Action items

1. Turn on a multi region CloudTrail trail so the "who made this change" question can be answered.
2. Run the scheduled scan on infrastructure with a reliable schedule, such as an EventBridge rule and a Lambda, instead
   of relying on GitHub's best effort timer.
3. Consider blocking manual edits to security groups with a service control policy, so drift is rare in the first
   place.
