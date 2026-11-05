# Runbook: what to do when Cloud Drift Guard alerts

Every alert in Slack shows a rule ID, the resource, and a one line fix. Start here.

## First two minutes, for any alert

1. Read the rule ID and the resource name in the alert.
2. Ask: did someone on the team just make this change on purpose? Check the team channel and recent pull requests.
3. If yes, update the Terraform code so it matches, and the alert goes away on the next scan.
4. If no, treat it as a real incident and follow the matching section below.

## DRIFT (a resource changed outside Terraform)

Meaning: the live setting no longer matches what Terraform says it should be.

1. Run `terraform plan` in the terraform folder. It shows exactly what differs.
2. If the change was a mistake, run `terraform apply` to put it back.
3. If the change was needed, edit the code to match and open a pull request.
4. Ask the person who made the change to use Terraform next time.

## SG-SSH-OPEN or SG-ALL-OPEN (a firewall group allows the whole internet)

1. Find what is attached to the group: EC2 console, Network Interfaces, filter by the group ID.
2. If nothing is attached, delete the rule right away.
3. If something is attached, replace the rule with your office or VPN address range.
4. Check CloudTrail for who made the change and when.

## S3-PUBLIC (a bucket is readable by anyone)

1. Turn on all four Block Public Access settings for the bucket.
2. Check what is inside the bucket and whether anything private was exposed.
3. Check the bucket access logs for reads from unknown addresses during the exposed window.
4. If private data was exposed, tell the security lead.

## IAM-ADMIN-USER and IAM-NO-MFA (a powerful or unprotected person account)

1. Remove the wildcard policy and attach only the permissions the person needs.
2. Require MFA on the account before it signs in again.
3. Rotate that user's access keys.

## COST-JUMP (daily spend rose sharply)

1. Open Cost Explorer, group by service, and find what grew.
2. Look for a running instance, a large volume, or data transfer nobody expected.
3. Stop or delete the cause, then set a budget alert so the next jump is caught earlier.

## After the incident

Write a short postmortem: what happened, how long until the alert, how long until the fix, and what stops it happening again.
