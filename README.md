# Cloud Drift Guard

A scanner for an AWS account. It looks for security mistakes, wasted spend and drift (things that were
changed by hand after Terraform built them). It tells you what is wrong and how to fix it, alerts on
Slack only when something is new, and can open a pull request for the few fixes that are safe to automate.

I built it for small teams that do not have a cloud engineer.

## What it checks

| Rule | What it looks for | Kind |
|---|---|---|
| S3-PUBLIC | Bucket open to everyone with public access not blocked | security |
| S3-VERSIONING | Bucket without versioning | security |
| S3-LOGGING | Bucket without access logging | security |
| SG-SSH-OPEN | SSH (port 22) open to the internet | security |
| SG-ALL-OPEN | Every port open to the internet | security |
| SG-DEFAULT-RULES | Inbound rules on the default security group | security |
| EBS-UNENCRYPTED | Unencrypted volume | security |
| IAM-ADMIN-USER | User with a policy that allows every action on every resource | security |
| IAM-NO-MFA | Console user without MFA | security |
| IAM-OLD-KEY | Active access key older than 90 days | security |
| LAMBDA-OLD-RUNTIME | Function on a retired runtime | security |
| ACCT-NO-PW-POLICY | No IAM password policy | security |
| ACCT-ROOT-KEY | Root user has an access key | security |
| ACCT-NO-CLOUDTRAIL | No CloudTrail trail | security |
| EBS-UNATTACHED | Volume attached to nothing | waste |
| EIP-UNUSED | Elastic IP attached to nothing | waste |
| EC2-IDLE | Running instance under 5% CPU for 7 days | waste |
| COST-JUMP | Daily spend up 1.5x or more against the week before | waste |
| DRIFT | Security group rules, volume size or encryption, instance type or bucket versioning differ from the Terraform state, or the resource was deleted | drift |
| DRIFT-UNTRACKED | A security group, volume, instance or bucket exists in AWS but not in Terraform | drift |

Each rule is a small function in `scanner/rules/` with its own test.

## How it fits together

```
scan or schedule -> rules, drift check and cost check -> findings table (SQLite)
                 -> new findings only -> Slack alert
                 -> safe findings -> pull request with Terraform fix files
```

The findings table is what keeps alerts rare. A finding is sent once, again only if it was fixed and came back.

## Try it without touching a real account

The sample environment in `terraform/` plants 12 mistakes on purpose. You can run it against a fake AWS (a moto
server that runs on your machine, free and with no account), so nothing is created in a real account.

```
pip install -r requirements-dev.txt
make test                 # all tests, no AWS needed
make moto-up
make tf-init
make tf-apply-local       # plants the 12 mistakes
make measure-local        # scans, then prints "Caught N of 12 planted mistakes."
make drift-local          # compares Terraform state with what is in the fake account
make moto-down
```

The tests run the same measurement on an emulated account (`tests/test_planted_issues.py`): 12 planted mistakes,
all found, and no findings on the correctly configured resources.

## Using it on a real account

The scanner only reads. Give it a read only role (the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies should
cover the rules, plus `ce:GetCostAndUsage` for cost).

```
python -m scanner.cli scan --json findings.json
python -m scanner.cli scan --slack          # needs SLACK_WEBHOOK_URL
python -m scanner.cli drift                 # runs terraform show -json in ./terraform
python -m scanner.cli cost                  # one Cost Explorer call, about one cent
python -m scanner.cli fix-pr --repo owner/name          # dry run
python -m scanner.cli fix-pr --repo owner/name --open   # needs GITHUB_TOKEN
```

To plant the mistakes on real AWS, set `name_suffix` to something unique such as `-<your account id>`, and set
`plant_old_lambda=false`, because AWS stops allowing new functions on retired runtimes. Destroy it with
`terraform destroy` when you are done. Everything in the sample environment is free or a few cents.

## Results on a real AWS account

I ran this against a real AWS account (a new account on the free plan, us-east-1) using a read only user.

- **Before planting anything**, the scan found 5 real issues in the fresh account: no CloudTrail trail, no IAM
  password policy, inbound rules on the default security group, and a SageMaker bucket with no versioning or access
  logging.
- **Planted mistakes:** Terraform created 22 resources, 11 of them deliberate mistakes. The scanner caught
  **11 of 11**. The twelfth planted mistake, a function on a retired runtime, is skipped on real AWS because AWS
  refuses to create one.
- **Waste:** it flagged about $3.73 a month. That matches the unused Elastic IP ($3.65) plus a 1 GB unattached
  volume ($0.08).
- **Drift:** I opened SSH to the whole internet on a security group by hand in the console. The drift check flagged
  it as high severity and sent a Slack alert. I ran the check by hand about a minute after the change, so this shows
  that detection works, not how fast a schedule would catch it. It also flagged a bucket that exists in AWS but not
  in Terraform, which was a true finding (the SageMaker SDK created it).
- **Timing and the full incident:** with a scan running every 60 seconds from a timer on my laptop, I added an "all
  traffic from anywhere" rule to a security group at 17:46:08. The next scan found it 10 seconds later and the Slack
  alert arrived in the same minute. That was lucky timing: a scan takes about 25 seconds, so the worst case is about
  85 seconds. I fixed it with `terraform apply` at 17:48:34 and the next scan confirmed it, 14 seconds later. The write
  up is in `docs/postmortem.md` and the response steps are in `docs/runbook.md`.
- **Slack:** a real alert with the new findings arrived in a channel. A repeat scan with nothing changed reported 0 new findings, so there was nothing to send.
- **Fix pull request:** it opened a real pull request with two safe fixes (S3 versioning and a password policy)
  against a separate demo repo: https://github.com/manaswichowdary/drift-guard-demo-infra/pull/1
- **Cost Explorer:** the real call reached AWS but returned "data not available", because Cost Explorer takes up to
  24 hours to fill on a new account. The tool now prints a clear message instead of a stack trace. The spend jump
  logic is covered by tests, and not yet by real data.

## Decisions I made

**Which fixes run automatically.** Only three rules get an automatic pull request: S3 versioning, S3 public access
block and an IAM password policy. Each one only adds protection and cannot lock anyone out or delete data. Closing
an SSH rule could cut off a person who needs it, and deleting a volume loses data, so those only alert.

**Smallest permissions.** The scanner needs read access only. It never changes anything in AWS. The fix pull
request is the only write, and it goes to GitHub, where a person reviews it.

**Keeping alerts rare.** Findings are stored, and only new ones are sent. A Slack message is capped at 10 lines and
sorted worst first. Cost jumps need at least $1 a day, so a change from 2 cents to 5 cents does not page anyone.

**Waste estimates are rough.** Unused volumes are priced at gp3 list price and unused Elastic IPs at the public IPv4
hourly rate. Idle instances are flagged but not priced.

## Results

Run against a fake AWS (moto server), with the Terraform sample environment applied:

- **Planted mistakes caught:** 12 of 12 (`make measure-local`).
- **Drift:** with nothing changed, 0 findings. After adding an inbound rule by hand, 1 finding that shows the rule
  Terraform expected against the rules AWS has.
- **Tests:** 48 passing. They include the same 12 planted mistakes on an emulated account, with no findings on the
  correctly configured resources.

The scan also reports 4 findings I did not plant, all true: no CloudTrail trail, no password policy, and the log
bucket itself has no versioning or access logging.

Not measured yet: minutes from drift to alert, false alerts per week, and a run against a real AWS account.

## Status

- Done: 17 security and waste rules, drift check, cost jump check, findings table, Slack alert format, safe fix
  proposals, pull request opener, Terraform environment with planted mistakes, measurement tool, CI, a runbook, a
  postmortem for one simulated incident, and a scheduled scan workflow (GitHub Actions, every 5 minutes).
- Run on a real AWS account: 11 of 11 planted mistakes caught, a real Slack alert, a real fix pull request, and real
  drift caught. Details are in the results section above.
- Not proven yet: the GitHub schedule itself (the workflow works when started by hand and takes about 18 seconds,
  but GitHub had not started its first scheduled run after more than 40 minutes), and a real Cost Explorer result
  (AWS needs up to 24 hours to fill data on a new account).
- Not built: a Lambda and EventBridge deployment, which would be a more reliable schedule than GitHub's.
