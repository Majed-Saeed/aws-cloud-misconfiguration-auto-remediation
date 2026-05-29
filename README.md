# AWS Cloud Misconfiguration Detection and Auto-Remediation Framework

A serverless cloud security automation framework that detects AWS security misconfigurations, automatically remediates supported issues, sends real-time notifications, and maintains an audit trail using AWS native services.

---

## 📌 Project Overview

Cloud misconfigurations are one of the most common causes of security incidents in cloud environments. This project was developed to automatically detect non-compliant AWS resources and respond without manual intervention.

The system uses AWS Config to monitor resources, Amazon EventBridge to process compliance events, AWS Lambda to perform remediation actions, Amazon SNS to send notifications, and Amazon DynamoDB to maintain remediation audit logs.

---

## 🚀 Features

- Continuous compliance monitoring using AWS Config
- Event-driven remediation using Amazon EventBridge
- Automated remediation using AWS Lambda
- Real-time email notifications via Amazon SNS
- Audit logging with Amazon DynamoDB
- CloudWatch monitoring and execution logs
- Fully serverless architecture

---

## 🏗️ AWS Services Used

- AWS Config
- Amazon EventBridge
- AWS Lambda
- Amazon S3
- Amazon EC2
- Amazon SNS
- Amazon DynamoDB
- Amazon CloudWatch
- AWS IAM

---

## ⚙️ Architecture

```text
AWS Config
     │
     ▼
EventBridge
     │
     ▼
AWS Lambda
(Auto-Remediation)
     │
 ┌───┴───────────┐
 ▼               ▼
SNS          DynamoDB
Alerts       Audit Logs
```

---

## 🔥 Implemented Compliance Rules

### S3 Public Read Detection

**Rule**

```text
s3-bucket-public-read-prohibited
```

**Automated Action**

- Block public access
- Remove public bucket policy
- Send SNS notification
- Store audit log

---

### S3 Public Write Detection

**Rule**

```text
s3-bucket-public-write-prohibited
```

**Automated Action**

- Block public access
- Remove public bucket policy
- Send SNS notification
- Store audit log

---

### Restricted SSH Detection

**Rule**

```text
restricted-ssh
```

**Automated Action**

- Remove inbound SSH rule (Port 22)
- Send SNS notification
- Store audit log

---

### IAM User MFA Monitoring

**Rule**

```text
iam-user-mfa-enabled
```

**Action**

- Alert only
- Manual remediation required

---

### Root Account MFA Monitoring

**Rule**

```text
root-account-mfa-enabled
```

**Action**

- Alert only
- Manual remediation required

---

## 🧠 Lambda Function Responsibilities

The remediation Lambda function performs the following actions:

- Receive AWS Config compliance events
- Identify violated compliance rule
- Execute remediation logic
- Log remediation activity to DynamoDB
- Send SNS notification
- Store execution logs in CloudWatch

---

## 🔄 Workflow

### Example: Public S3 Bucket

1. An S3 bucket becomes publicly accessible
2. AWS Config detects the violation
3. Resource becomes **NON_COMPLIANT**
4. EventBridge receives the compliance event
5. Lambda function is invoked
6. Public access is blocked automatically
7. SNS sends an email notification
8. DynamoDB stores an audit record
9. CloudWatch stores execution logs

---

## 🗄️ DynamoDB Audit Logging

**Table Name**

```text
RemediationAuditLog
```

### Logged Information

- Unique ID
- Timestamp
- Rule Name
- Resource ID
- Resource Type
- Remediation Status
- Action Performed

### Example Record

```json
{
  "rule": "restricted-ssh",
  "resource_id": "sg-123456789",
  "resource_type": "AWS::EC2::SecurityGroup",
  "status": "REMEDIATED",
  "action": "SSH port 22 closed"
}
```

---

## 📧 SNS Notification Example

```text
Cloud Misconfiguration Auto-Remediation Report

Rule:
s3-bucket-public-read-prohibited

Resource:
example-bucket

Action:
S3 public access blocked + policy deleted

Status:
REMEDIATED
```

---

## 📸 Screenshots

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

### SNS Notification

![SNS Notification](screenshots/sns-alert-email.png)

---

### CloudWatch Logs

![CloudWatch Logs](screenshots/cloudwatch-logs.png)

---

## 📁 Repository Structure

```text
.
├── lambda/
│   └── auto-remediate-s3-public-access.py
│
├── screenshots/
│   ├── aws-config-rules.png
│   ├── eventbridge-rule.png
│   ├── lambda-function.png
│   ├── iam-permissions.png
│   ├── dynamodb-audit-log.png
│   ├── sns-alert-email.png
│   └── cloudwatch-logs.png
│
├── README.md
├── LICENSE
├── .gitignore
└── progress-log.md
```

---

## ✅ Current Status

Implemented and configured:

- AWS Config compliance monitoring
- EventBridge event routing
- Lambda auto-remediation
- SNS email notifications
- DynamoDB audit logging
- CloudWatch monitoring

---

## 📈 Future Improvements

- Principle of Least Privilege IAM policies
- Custom AWS Config Rules
- Security dashboard
- Multi-account monitoring
- AWS Security Hub integration
- Automated compliance reporting
- Additional AWS resource coverage

---

## 🎓 Academic Purpose

This project was developed as a Final Year Project (FYP) to demonstrate cloud security automation, compliance monitoring, and automated remediation using AWS native services.

---

## 📄 License

This project is licensed under the MIT License.
