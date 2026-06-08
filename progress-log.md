# Cloud Misconfiguration Detection and Auto-Remediation System for AWS

## Phase 1 — AWS Config Setup ✅
- Enabled AWS Config in us-east-1 region
- Created S3 logging bucket
- Enabled continuous configuration recording
- Added AWS managed rules:
  - `s3-bucket-public-read-prohibited`
  - `s3-bucket-public-write-prohibited`
  - `restricted-ssh`
  - `iam-user-mfa-enabled`
  - `root-account-mfa-enabled`
- Created custom AWS Config rule:
  - `honeypot-port-detection`

## Phase 2 — Amazon EventBridge ✅
- Created EventBridge rule to capture Config compliance change events
- Filtered to trigger only on `NON_COMPLIANT` events
- Connected target to Lambda function

## Phase 3 — AWS Lambda Remediation Function ✅
- Created function `remediate-s3-public-access` (Python 3.12)
- Handles misconfiguration remediation for:
  - S3 public access
  - SSH exposure
  - RDP exposure
  - RDS public accessibility
  - IAM MFA findings
- Attached required IAM permissions (S3, EC2, RDS, IAM, DynamoDB, SNS)

## Phase 4 — Custom Detection Engine ✅
- Created custom Lambda function `FYP1-Custom-Rule`
- Detects publicly exposed high-risk ports
- Supports AWS Config and EventBridge events
- Monitors:
  - SSH (22)
  - Telnet (23)
  - RDP (3389)
  - VNC (5900)
  - SQL Server (1433)
  - MySQL (3306)
  - PostgreSQL (5432)

## Phase 5 — Amazon SNS Notifications ✅
- Created topic `cloud-misconfig-alerts`
- Subscribed admin email
- Email alert sent on every detection and remediation

## Phase 6 — DynamoDB Audit Logging ✅
- Created audit tables for remediation and security findings
- Logs rule, resource, action, status, and timestamp

## Phase 7 — S3 Audit Logging ✅
- Stores security findings in CSV format
- Maintains historical audit records for review and reporting

## Phase 8 — Testing ✅
- Created test S3 bucket `fyp-public-test-123`
- Made it public intentionally
- System detected, remediated, logged, and sent email automatically
- Tested public SSH exposure detection and remediation
- Validated high-risk port detection workflow

Phase 9 — Additional Testing ✅
	•	Re-tested S3 public access remediation
	•	Re-tested SSH exposure detection
	•	Verified audit log generation
	•	Verified SNS notification delivery