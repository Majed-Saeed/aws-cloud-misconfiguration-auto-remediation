# AWS Cloud Misconfiguration Auto-Remediation

An AWS serverless security automation project developed as a Final Year Project (FYP) to detect cloud misconfigurations, automatically remediate security issues, notify administrators, and maintain an audit trail using AWS native services.

---

## Project Overview

Cloud misconfigurations remain one of the most common causes of security incidents in cloud environments. Manual monitoring and remediation can be slow, error-prone, and difficult to scale.

This project implements an automated cloud security remediation framework that continuously monitors AWS resources using AWS Config, detects non-compliant configurations, triggers automated remediation through AWS Lambda, records remediation activities in DynamoDB, and sends security notifications through Amazon SNS.

The solution follows an event-driven serverless architecture and demonstrates how AWS native services can be combined to improve cloud security posture with minimal operational overhead.

---

## Objectives

- Detect AWS cloud security misconfigurations automatically.
- Perform remediation actions without manual intervention.
- Generate real-time security alerts.
- Maintain remediation audit logs for tracking and reporting.
- Demonstrate practical implementation of cloud security automation.
- Reduce response time to cloud security incidents.

---

## Key Features

### Detection

- AWS Config compliance monitoring
- Real-time event detection
- Continuous resource evaluation

### Automated Remediation

- Block public S3 bucket access
- Remove insecure bucket policies
- Close publicly exposed SSH access (Port 22)
- Close publicly exposed RDP access (Port 3389)
- Disable public accessibility for Amazon RDS instances

### Alerting

- Email notifications using Amazon SNS
- Remediation status reporting
- Security incident visibility

### Audit Logging

- DynamoDB remediation records
- Historical remediation tracking
- Event auditing and reporting

### Monitoring

- CloudWatch Logs integration
- Lambda execution monitoring
- Operational visibility

---

## AWS Services Used

| Service | Purpose |
|----------|----------|
| AWS Config | Detect cloud misconfigurations |
| Amazon EventBridge | Trigger remediation workflows |
| AWS Lambda | Execute remediation actions |
| Amazon S3 | Security monitoring target |
| Amazon EC2 | Security group remediation |
| Amazon RDS | Database security remediation |
| Amazon SNS | Email alert notifications |
| Amazon DynamoDB | Audit logging |
| Amazon CloudWatch | Monitoring and logging |
| AWS IAM | Access management and permissions |

---

## System Architecture

```text
                    AWS Config
                         │
                         ▼
              Compliance Evaluation
                         │
                         ▼
                  EventBridge Rule
                         │
                         ▼
                 AWS Lambda Function
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
    Remediation      SNS Alert      DynamoDB Log
        │                │                │
        ▼                ▼                ▼
      AWS            Email Alert      Audit Trail
   Resources
```

---

## Implemented Security Controls

### S3 Public Access Protection

AWS Config Rules:

```text
s3-bucket-public-read-prohibited
s3-bucket-public-write-prohibited
```

Remediation Actions:

- Enable S3 Public Access Block
- Block public ACLs
- Ignore public ACLs
- Block public bucket policies
- Restrict public bucket access
- Remove insecure bucket policies

---

### EC2 Security Group Protection

AWS Config Rule:

```text
restricted-ssh
```

Remediation Action:

```text
Remove inbound SSH access from 0.0.0.0/0
```

---

### RDP Exposure Protection

AWS Config Rule:

```text
restricted-rdp
```

Remediation Action:

```text
Remove inbound RDP access from 0.0.0.0/0
```

---

### Amazon RDS Security Protection

AWS Config Rule:

```text
rds-instance-public-access-check
```

Remediation Action:

```text
Disable public accessibility
```

---

### MFA Compliance Monitoring

AWS Config Rules:

```text
iam-user-mfa-enabled
root-account-mfa-enabled
```

Current Action:

```text
Alert Only
```

Manual remediation is required because enabling MFA requires user interaction.

---

## Lambda Remediation Workflow

When AWS Config detects a non-compliant resource:

1. AWS Config evaluates resource compliance.
2. EventBridge receives the compliance event.
3. EventBridge triggers the remediation Lambda.
4. Lambda identifies the violated rule.
5. Appropriate remediation action is executed.
6. Remediation result is stored in DynamoDB.
7. SNS notification is sent to administrators.
8. CloudWatch stores execution logs.

---

## DynamoDB Audit Log Structure

Each remediation action is recorded with:

| Field | Description |
|---------|-------------|
| id | Unique record identifier |
| timestamp | Remediation timestamp |
| rule | AWS Config rule name |
| resource_id | Affected resource |
| resource_type | Resource type |
| status | Remediation status |
| action | Remediation action performed |

---

## Project Structure

```text
AWS-Cloud-Misconfiguration-Auto-Remediation/
│
├── lambda/
│   └── auto-remediation.py
│
├── screenshots/
│   ├── aws-config-rules.png
│   ├── eventbridge-rule.png
│   ├── lambda-function.png
│   ├── iam-permissions.png
│   ├── dynamodb-audit-log.png
│   ├── cloudwatch-logs.png
│   └── sns-alert-email.png
│
├── README.md
├── LICENSE
└── .gitignore
```

---

## Screenshots

### AWS Config Rules

![AWS Config Rules](screenshots/aws-config-rules.png)

---

### EventBridge Rule

![EventBridge Rule](screenshots/eventbridge-rule.png)

---

### Lambda Function

![Lambda Function](screenshots/lambda-function.png)

---

### IAM Permissions

![IAM Permissions](screenshots/iam-permissions.png)

---

### DynamoDB Audit Log

![DynamoDB Audit Log](screenshots/dynamodb-audit-log.png)

---

### CloudWatch Logs

![CloudWatch Logs](screenshots/cloudwatch-logs.png)

---

### SNS Email Notification

![SNS Alert Email](screenshots/sns-alert-email.png)

---

## Testing and Validation

The system was tested by intentionally creating AWS cloud security misconfigurations and observing the automated response.

### Example Test Scenario

1. Create a public S3 bucket configuration.
2. AWS Config detects the violation.
3. EventBridge receives the compliance event.
4. Lambda executes remediation.
5. Public access is blocked automatically.
6. SNS notification is delivered.
7. DynamoDB stores remediation details.
8. CloudWatch records execution logs.

### Result

```text
Status: REMEDIATED
```

The misconfiguration was successfully detected and corrected automatically without administrator intervention.

---

## Benefits of the Proposed Solution

- Improved cloud security posture
- Faster incident response
- Reduced human error
- Automated compliance enforcement
- Centralized audit logging
- Scalable serverless architecture
- Low operational overhead

---

## Limitations

- Some AWS Config rules require manual remediation.
- MFA-related violations cannot be remediated automatically.
- Current implementation focuses on selected AWS services.
- Additional security controls can be added in future versions.

---

## Future Enhancements

- Custom AWS Config Rules
- Principle of Least Privilege IAM policies
- Security dashboard and analytics
- Additional remediation playbooks
- Multi-account support
- CloudTrail integration
- Security reporting dashboard
- Automated compliance reports
- AI-assisted remediation recommendations

---

## Author

**Maged Saeed**

Final Year Project (FYP)

Cloud Security Automation Using AWS Native Services

---

## License

This project is licensed under the MIT License.
