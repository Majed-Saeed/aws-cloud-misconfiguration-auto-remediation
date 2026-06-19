<div align="center">

# ☁️ AWS Cloud Misconfiguration Auto-Remediation
### with Real-Time Risk Scoring & Evasion-Resistant Detection

**A serverless, event-driven security pipeline that detects cloud misconfigurations in real time, scores their risk.**

<br/>

[![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900?style=for-the-badge&logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![AWS Lambda](https://img.shields.io/badge/Lambda-Event_Driven-FF9900?style=for-the-badge&logo=awslambda&logoColor=white)](https://aws.amazon.com/lambda/)
[![Tested](https://img.shields.io/badge/Tested-Live_AWS-22C55E?style=for-the-badge)](#-results)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<sub>

[Overview](#-overview) • [Contribution](#-key-contribution) • [Risk Engine](#-risk-scoring-engine) • [Evasion Detection](#-evasion-resistant-detection) • [Architecture](#-architecture) • [How It Works](#-how-it-works) • [Results](#-results) • [Deployment](#-deployment) • [Future Work](#-future-work)

</sub>

</div>

<br/>

<div align="center">

| 🎓 Project | 🌍 Region | 🐍 Runtime | ⚡ Model | ✅ Status |
|:---:|:---:|:---:|:---:|:---:|
| Final Year Project | us-east-1 | Python 3.12 | Event-driven | Working & tested |

</div>

---

## 📖 Overview

Cloud misconfigurations — a publicly readable S3 bucket, or a high-risk port left open to the internet — are among the most common causes of cloud security incidents. The real danger lives in the **window between a misconfiguration appearing and it being fixed**. Manual monitoring is slow, easy to miss across many resources, and reactive.

AWS provides **AWS Config** to *detect* such misconfigurations, but in a default setup Config rules are **detective-only**: they flag a non-compliant resource and stop there. The resource stays exposed until a human intervenes.

This project closes that gap. It implements a **serverless, event-driven remediation pipeline** that:

1. **Detects** high-risk security-group exposure in real time via **CloudTrail → EventBridge → Lambda**.
2. **Scores** each finding with a custom **Risk Scoring Engine** (0–100 + HIGH / MEDIUM / LOW).
3. **Remediates** the exposure automatically, closing the offending rule in seconds.
4. **Resists evasion** by analysing the true breadth of a CIDR rather than string-matching `0.0.0.0/0`.
5. **Alerts and audits** every action through SNS email, a DynamoDB record, an S3 CSV trail, and CloudWatch logs.

The system was deployed and tested in a **live AWS account** (`us-east-1`), and validated with an automated, repeatable test harness.

<div align="center">

| 🔍 Detect | 🧮 Score | 🛠️ Remediate | 📣 Alert | 🧾 Audit |
|:---:|:---:|:---:|:---:|:---:|
| CloudTrail + Config | Risk Engine (0–100) | Lambda revoke | SNS email | DynamoDB · S3 · CloudWatch |

</div>

---

## 🎯 Key Contribution

This project is an **enhancement** of native cloud security tooling. Standard AWS Config rules answer one binary question — *"is this resource compliant?"* — and, by default, take no action. This work adds three capabilities that AWS Config does not provide out of the box:

| # | Contribution | What it adds beyond AWS native behaviour |
|:--:|:---|:---|
| **1** | **Real-time auto-remediation** | AWS Config is detect-only in the default configuration; this system **closes** the exposure automatically, within seconds. |
| **2** | **Risk Scoring Engine** | A weighted 0–100 risk score and HIGH/MEDIUM/LOW level for every finding, instead of a binary compliant / non-compliant flag. |
| **3** | **Evasion-resistant detection** | Detects internet exposure by **CIDR breadth analysis**, catching split-CIDR and wide-block techniques that exact-string matching (`0.0.0.0/0`) misses. |

> All three contributions live in the detection/decision logic of the `FYP1-Custom-Rule` Lambda — they are original work layered on top of AWS's native event and compliance services.

---

## 🧮 Risk Scoring Engine

Rather than treating every exposed port identically, the engine assigns each finding a **0–100 risk score** built from four weighted factors. This lets an administrator prioritise: a database port briefly exposed to a narrow range is not the same emergency as RDP opened to the entire internet.

<div align="center">

| Factor | Max points | Rationale |
|:---|:---:|:---|
| **Port sensitivity** | 40 | RDP/SSH (remote shell) weighted above database ports |
| **Exposure breadth** | 30 | Derived from the CIDR's true size (the evasion-resistant input) |
| **Port-range width** | 20 | Opening many ports at once is riskier than a single port |
| **Protocol openness** | 10 | "All traffic" (`-1`) is the maximum-risk protocol setting |

</div>

**Risk levels:** `HIGH ≥ 70` · `MEDIUM 40–69` · `LOW < 40`

**Port sensitivity weights**

<div align="center">

| Port | Service | Weight | Port | Service | Weight |
|:---:|:---|:---:|:---:|:---|:---:|
| 3389 | RDP | 40 | 1433 | SQL Server | 28 |
| 22 | SSH | 38 | 3306 | MySQL | 28 |
| 23 | Telnet | 36 | 5432 | PostgreSQL | 28 |
| 5900 | VNC | 34 | | | |

</div>

Every alert email, DynamoDB record, and S3 audit row now carries the **risk score** and **risk level** — the structured severity that native Config output lacks.

---

## 🛡️ Evasion-Resistant Detection

A naïve detector (and AWS Config's exposure checks) typically look for the **exact** CIDR string `0.0.0.0/0`. An attacker — or a careless administrator — can expose a resource to the entire internet **without ever using that string**:

<div align="center">

| Evasion technique | Why it bypasses exact-match | Real exposure |
|:---|:---|:---:|
| `0.0.0.0/1` + `128.0.0.0/1` | Neither equals `0.0.0.0/0` | Entire internet |
| `0.0.0.0/4` | A single huge block, not the magic string | ~268M addresses |
| `1.0.0.0/8` | Wide block | ~16M addresses |
| Port range `20–25` | Hides SSH (22) inside a range | Port 22 exposed |

</div>

This system **parses the CIDR and measures its true breadth** (using Python's `ipaddress` module). Any rule whose prefix is wide enough to be effectively internet-facing is flagged — and, critically, the **remediation revokes the exact CIDR that was opened**, not a hardcoded `0.0.0.0/0`. This evasion-aware remediation is what allows the system to actually *close* split-CIDR rules, not just detect them.

> Evasion detection is controlled by the `EVASION_DETECTION` environment variable. Setting it to `false` reproduces the naïve baseline — this is used directly in the evaluation (Experiment 2) to measure the improvement.

---

## ✅ Implemented Controls

<div align="center">

| Control | Detection Source | Action |
|:---|:---|:---:|
| **High-Risk Port Exposure** (SSH, Telnet, RDP, VNC, SQL Server, MySQL, PostgreSQL) | CloudTrail + custom Lambda rule | 🛠️ Detect · Score · Auto-Remediate |
| **S3 Public Read** | `s3-bucket-public-read-prohibited` (AWS managed) | 🔔 Detect |
| **S3 Public Write** | `s3-bucket-public-write-prohibited` (AWS managed) | 🔔 Detect |
| **SSH Exposure (EC2)** | `restricted-ssh` (AWS managed) | 🔔 Detect |
| **IAM User MFA** | `iam-user-mfa-enabled` (AWS managed) | 🔔 Detect · Alert |
| **Root Account MFA** | `root-account-mfa-enabled` (AWS managed) | 🔔 Detect · Alert |

</div>

> **Honest scope note.** In the current deployment, the AWS-managed Config rules above run in **detective mode** (remediation action *Not set*) — they flag non-compliance but do not auto-close. The **custom high-risk-port path is the component that performs real-time auto-remediation, scoring, and evasion-resistant detection**, and is therefore the focus of this project's contribution and evaluation. MFA findings are inherently alert-only, since enabling MFA requires manual user enrolment and cannot be remediated programmatically.

**High-risk ports monitored**

<div align="center">

| Port | Service | Port | Service |
|:---:|:---|:---:|:---|
| 22 | SSH | 3306 | MySQL |
| 23 | Telnet | 5432 | PostgreSQL |
| 1433 | SQL Server | 5900 | VNC |
| 3389 | RDP | | |

</div>

**Supporting capabilities**

- 📣 Email alerting through Amazon SNS (now including risk score, level, and a score breakdown)
- 🧾 Structured audit trail in Amazon DynamoDB **and** a versioned CSV trail in Amazon S3
- 📊 Execution monitoring in Amazon CloudWatch
- 🏷️ Whitelisting via resource tag (`Approved = true`) so approved exceptions are skipped

---

## 🏗️ Architecture

Fully serverless and event-driven — no servers to manage; every component scales and bills on demand.

```text
        Security-group change (e.g. a high-risk port opened to the internet)
                              │
                              ▼
                    AWS CloudTrail   (records the API call)
                              │
                              ▼
                  Amazon EventBridge (matches AuthorizeSecurityGroupIngress)
                              │
                              ▼
            AWS Lambda · FYP1-Custom-Rule
            ┌─────────────────────────────────────────────┐
            │  1. CIDR breadth analysis (evasion-resistant)│
            │  2. Risk Scoring Engine (0–100 + level)      │
            │  3. Auto-remediation (revoke exact CIDR)     │
            └─────────────────────────────────────────────┘
                              │
        ┌─────────────┬───────┴────────┬──────────────┬───────────────┐
        ▼             ▼                ▼              ▼               ▼
   Revoke rule    SNS email      DynamoDB record   S3 CSV log    CloudWatch logs
```

> AWS Config also evaluates a custom `honeypot-port-detection` rule and the managed S3/SSH/MFA rules, feeding compliance findings into the same Lambda for scoring and alerting.

---

## 🧰 AWS Services Used

<div align="center">

![Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=flat-square&logo=awslambda&logoColor=white)
![Config](https://img.shields.io/badge/AWS_Config-FF9900?style=flat-square&logo=amazonwebservices&logoColor=white)
![CloudTrail](https://img.shields.io/badge/CloudTrail-FF4F8B?style=flat-square&logo=amazonwebservices&logoColor=white)
![EventBridge](https://img.shields.io/badge/EventBridge-FF4F8B?style=flat-square&logo=amazonwebservices&logoColor=white)
![S3](https://img.shields.io/badge/Amazon_S3-569A31?style=flat-square&logo=amazons3&logoColor=white)
![EC2](https://img.shields.io/badge/Amazon_EC2-FF9900?style=flat-square&logo=amazonec2&logoColor=white)
![DynamoDB](https://img.shields.io/badge/DynamoDB-4053D6?style=flat-square&logo=amazondynamodb&logoColor=white)
![SNS](https://img.shields.io/badge/Amazon_SNS-FF4F8B?style=flat-square&logo=amazonsimplequeueservice&logoColor=white)
![CloudWatch](https://img.shields.io/badge/CloudWatch-FF4F8B?style=flat-square&logo=amazoncloudwatch&logoColor=white)
![IAM](https://img.shields.io/badge/AWS_IAM-DD344C?style=flat-square&logo=amazonwebservices&logoColor=white)
![Python](https://img.shields.io/badge/Python_3.12-3776AB?style=flat-square&logo=python&logoColor=white)

</div>

| Service | Role in the Project |
|:---|:---|
| **AWS CloudTrail** | Records security-group API calls so EventBridge can react in real time |
| **Amazon EventBridge** | Routes CloudTrail security-group events (and Config events) to the Lambda |
| **AWS Lambda** | Hosts the detection, risk scoring, evasion analysis, and remediation logic |
| **AWS Config** | Evaluates the custom `honeypot-port-detection` rule and managed S3/SSH/MFA rules (detective) |
| **Amazon EC2** | Security groups monitored for high-risk port exposure |
| **Amazon S3** | Destination for the versioned CSV audit log |
| **Amazon DynamoDB** | Stores the structured audit trail of every finding, including risk score & level |
| **Amazon SNS** | Sends email alerts via the `cloud-misconfig-alerts` topic |
| **Amazon CloudWatch** | Captures Lambda execution logs (also the source the test harness reads scores from) |
| **AWS IAM** | Provides the Lambda execution role and least-privilege permissions |

---

## ⚙️ How It Works

```text
 1. An inbound rule exposes a high-risk port to the internet
    (0.0.0.0/0, ::/0, OR a wide evasion CIDR such as 0.0.0.0/1, 1.0.0.0/8)
 2. CloudTrail records the AuthorizeSecurityGroupIngress API call
 3. EventBridge matches the call and invokes FYP1-Custom-Rule within seconds
 4. Lambda fetches the security group, skips it if tagged Approved=true,
    and analyses every ingress rule:
       - parses each CIDR and measures its true breadth
       - flags any internet-exposing rule (exact or wide/evasion)
 5. The Risk Scoring Engine assigns a 0–100 score and HIGH/MEDIUM/LOW level
 6. If AUTO_REMEDIATE=true, Lambda revokes the EXACT offending rule
    (the actual CIDR that was opened — this is what closes evasion rules)
 7. Lambda writes a DynamoDB record, appends to the S3 CSV audit log,
    and sends an SNS email containing the score, level, and breakdown
 8. CloudWatch records the full execution log
```

<details>
<summary><b>EventBridge event pattern (as deployed)</b></summary>

<br/>

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["AuthorizeSecurityGroupIngress", "CreateSecurityGroup"]
  }
}
```

</details>

> **Important:** detection depends on **CloudTrail being enabled**. EventBridge cannot see security-group API calls unless a CloudTrail trail is actively logging — this is a hard requirement for the real-time path to function.

---

## 🔧 Configuration

**`FYP1-Custom-Rule` environment variables**

| Key | Value | Purpose |
|:---|:---|:---|
| `AUTO_REMEDIATE` | `true` | Enable automatic closing of exposed ports |
| `EVASION_DETECTION` | `true` | Enable CIDR-breadth (evasion-resistant) detection |
| `WIDE_CIDR_PREFIX_V4` | `8` | IPv4 prefix ≤ this is treated as internet-exposed |
| `WIDE_CIDR_PREFIX_V6` | `32` | IPv6 prefix ≤ this is treated as internet-exposed |
| `SNS_TOPIC_ARN` | `arn:aws:sns:us-east-1:************:cloud-misconfig-alerts` | Alert topic |
| `DYNAMODB_TABLE` | `fyp-security-alerts` | Audit table |
| `AUDIT_BUCKET` | `fyp-audit-logs-************` | CSV audit-log bucket |
| `AUDIT_KEY` | `audit/high-risk-port-exposure.csv` | CSV object key |

**Least-privilege execution policy (high-risk-port Lambda)**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["ec2:DescribeSecurityGroups", "ec2:RevokeSecurityGroupIngress"],
      "Resource": "*" },
    { "Effect": "Allow", "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-1:************:cloud-misconfig-alerts" },
    { "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::fyp-audit-logs-************/*" },
    { "Effect": "Allow", "Action": "dynamodb:PutItem",
      "Resource": "arn:aws:dynamodb:us-east-1:************:table/fyp-security-alerts" },
    { "Effect": "Allow", "Action": "config:PutEvaluations", "Resource": "*" }
  ]
}
```

---

## 🧪 Results

The system was evaluated with an **automated test harness** that exercises the **live deployed Lambda** and records results to CSV. Critically, the harness does **not** recalculate anything locally — for scoring it reads the **actual score the Lambda produced**, parsed from CloudWatch Logs (with DynamoDB as a fallback); for detection it checks whether the **real Lambda removed the offending rule**.

### Experiment 1 — Time to Remediate (Speed)

RDP (3389) exposed to `0.0.0.0/0`, repeated over 5 trials.

<div align="center">

| Trial | Time to Remediate |
|:---:|:---:|
| 1 | 5.2 s |
| 2 | 2.9 s |
| 3 | 7.6 s |
| 4 | 5.3 s |
| 5 | 5.3 s |
| **Average** | **≈ 5.3 s** |

</div>

By comparison, **AWS Config in this account is detective-only** (remediation action *Not set* on all rules): it flags the exposure but **never closes the port**, so without this system the resource would remain exposed until a manual fix. The system reduces that window to **about five seconds, automatically**.

### Experiment 2 — Evasion Detection Rate

Each technique was applied to the live Lambda; detection = the rule was actually removed.

<div align="center">

| Technique | Naïve baseline | This system |
|:---|:---:|:---:|
| Direct `0.0.0.0/0` (SSH, RDP) | ✅ | ✅ |
| `0.0.0.0/1` (SSH) | ❌ | ✅ |
| `128.0.0.0/1` (RDP) | ❌ | ✅ |
| `0.0.0.0/4` (huge block) | ❌ | ✅ |
| `1.0.0.0/8` (wide block) | ❌ | ✅ |
| Port range `20–25` hiding SSH | ✅ | ✅ |
| Port range `3380–3400` hiding RDP | ✅ | ✅ |
| Safe `/24` private (must NOT flag) | ✅ ignored | ✅ ignored |
| Safe `/32` single IP (must NOT flag) | ✅ ignored | ✅ ignored |
| **Evasion-case detection rate** | **0 / 4 (0%)** | **4 / 4 (100%)** |

</div>

The naïve baseline detected **none** of the evasion techniques; this system detected and remediated **all** of them, while correctly leaving safe (narrow) rules untouched.

### Experiment 3 — Risk Score Validity

12 internet-exposed misconfigurations were triggered; the **actual score returned by the live Lambda** was compared against the severity a security analyst would expect.

<div align="center">

| Finding | Lambda Score | Level | Expected |
|:---|:---:|:---:|:---:|
| All traffic (`-1`) to internet | 100 | HIGH | HIGH ✅ |
| RDP range 3380–3400 | 84 | HIGH | HIGH ✅ |
| RDP 3389 to internet | 75 | HIGH | HIGH ✅ |
| SSH 22 to internet | 73 | HIGH | HIGH ✅ |
| SSH via evasion `0.0.0.0/1` | 73 | HIGH | HIGH ✅ |
| SSH via evasion `0.0.0.0/4` | 73 | HIGH | HIGH ✅ |
| Telnet 23 to internet | 71 | HIGH | HIGH ✅ |
| VNC 5900 to internet | 69 | MEDIUM | MEDIUM ✅ |
| SSH via `1.0.0.0/8` | 65 | MEDIUM | MEDIUM ✅ |
| MySQL 3306 to internet | 63 | MEDIUM | MEDIUM ✅ |
| PostgreSQL 5432 to internet | 63 | MEDIUM | MEDIUM ✅ |
| SQL Server 1433 to internet | 63 | MEDIUM | MEDIUM ✅ |
| **Accuracy** | | | **12 / 12 (100%)** |

</div>

The scores rank severity sensibly: "all traffic open" tops the scale, remote-shell ports (RDP/SSH/Telnet) land in HIGH, and database ports fall into MEDIUM.

### Summary

<div align="center">

| Claim | Metric | Result |
|:---|:---|:---:|
| **Faster** | Mean time to remediate | **≈ 5.3 s** (vs. AWS Config detective-only: never auto-closes) |
| **Smarter** | Evasion detection rate | **100%** (vs. naïve baseline **0%**) |
| **Sound** | Risk-score accuracy | **100%** (12 / 12) |

</div>

<details open>
<summary><b>Sample SNS alert — real-time, scored remediation</b></summary>

<br/>

```text
==================================================
  AWS CLOUD SECURITY ALERT
  High-Risk Port Exposure Detected
==================================================

  RISK SCORE      : 75 / 100
  RISK LEVEL      : [!!!] HIGH
  STATUS          : RESOLVED
  ACTION TAKEN    : AUTO-REMEDIATED

--------------------------------------------------
  RESOURCE DETAILS
--------------------------------------------------
  Security Group  : launch-wizard-2
  Group ID        : sg-0de9d27f7955c2ed9
  Exposed Ports   : 3389 (RDP)
  Ports Closed    : 3389 (RDP)

--------------------------------------------------
  RISK SCORE BREAKDOWN (worst finding)
--------------------------------------------------
  Port sensitivity  : 40 / 40
  Exposure breadth  : 30 / 30
  Port-range width  :  5 / 20
  Protocol openness :  0 / 10
==================================================
```

</details>

---

## 🚀 Deployment

**Prerequisites:** an AWS account, CloudTrail logging enabled, AWS CLI configured.

1. **Create supporting resources** — DynamoDB table (`fyp-security-alerts`), S3 audit bucket, SNS topic (`cloud-misconfig-alerts`) with an email subscription.
2. **Deploy the Lambda** — create `FYP1-Custom-Rule` (Python 3.12), paste `lambda/high-risk-ports.py`, set the environment variables from the table above, and attach the least-privilege policy.
3. **Wire the real-time path** — create an EventBridge rule using the event pattern above, targeting the Lambda.
4. **(Optional) AWS Config** — register the custom `honeypot-port-detection` rule and enable the managed S3/SSH/MFA rules for detective coverage.
5. **Verify** — open a high-risk port to `0.0.0.0/0`; within seconds you should receive a scored SNS alert and see the port auto-closed.

---

## 🧫 Test Harness

`fyp_test_harness.py` automates the full evaluation against the live system:

- Creates and later deletes a disposable test security group
- **Experiment 3** triggers misconfigurations and reads the **actual Lambda score** from CloudWatch/DynamoDB
- **Experiment 2** applies evasion techniques and verifies the **real Lambda** removed each rule
- **Experiment 1** measures end-to-end time to remediate over repeated trials
- Writes `exp1_speed_results.csv`, `exp2_evasion_results.csv`, `exp3_scoring_results.csv`

```bash
pip install boto3
python fyp_test_harness.py
```


## 📜 License

Released under the **MIT License** — see [LICENSE](LICENSE).

---

<div align="center">

### 👤 Author

**Maged Saeed**

<sub>Final Year Project — Cloud Security Automation on AWS<br/>
Detection · Risk Scoring · Evasion-Resistant Auto-Remediation</sub>

</div>
