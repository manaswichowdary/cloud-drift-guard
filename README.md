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
  proposals, pull request opener, Terraform environment with 12 planted mistakes, measurement tool, CI.
- Not done yet: a scheduled Lambda deployment, a runbook, a postmortem for a simulated incident, and a run against a
  real AWS account.
