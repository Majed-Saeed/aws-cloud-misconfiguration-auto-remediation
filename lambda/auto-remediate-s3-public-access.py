"""
High-Risk Port Exposure Detection & Auto-Remediation
Supports: AWS Config events + EventBridge (CloudTrail) events
Outputs : SNS alert, S3 CSV audit log, DynamoDB record
"""

import os
import io
import csv
import json
import uuid
from datetime import datetime, timezone

import boto3

# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------
HIGH_RISK_PORTS = {
    22:   "SSH",
    23:   "Telnet",
    3389: "RDP",
    5900: "VNC",
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
}

WHITELIST_TAG_KEY   = "Approved"
WHITELIST_TAG_VALUE = "true"

SNS_TOPIC_ARN  = os.environ.get("SNS_TOPIC_ARN", "")
AUDIT_BUCKET   = os.environ.get("AUDIT_BUCKET", "")
AUDIT_KEY      = os.environ.get("AUDIT_KEY", "audit/high-risk-port-exposure.csv")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "")
AUTO_REMEDIATE = os.environ.get("AUTO_REMEDIATE", "false").lower() == "true"

CSV_HEADER = ["timestamp_utc", "security_group_id", "security_group_name",
              "exposed_ports", "ports_closed", "action", "source"]

config_client = boto3.client("config")
ec2           = boto3.client("ec2")
sns           = boto3.client("sns")
s3            = boto3.client("s3")
dynamodb      = boto3.resource("dynamodb")


# -----------------------------------------------------------------
# Entry point - detects event source and routes
# -----------------------------------------------------------------
def lambda_handler(event, context):
    print("[EVENT] Received:", json.dumps(event, default=str)[:2000])

    # Safety: parse if event arrives as string
    if isinstance(event, str):
        event = json.loads(event)

    if "invokingEvent" in event:
        print("[ROUTER] AWS Config event detected")
        handle_config_event(event)
    elif "detail" in event:
        print("[ROUTER] EventBridge event detected")
        handle_eventbridge_event(event)
    else:
        print("[WARN] Unknown event source, skipping.")


# -----------------------------------------------------------------
# Handler: AWS Config
# -----------------------------------------------------------------
def handle_config_event(event):
    invoking_event = json.loads(event["invokingEvent"])
    result_token   = event.get("resultToken", "No token found.")
    config_item    = invoking_event.get("configurationItem") or {}

    resource_type = config_item.get("resourceType")
    resource_id   = config_item.get("resourceId")
    ci_status     = config_item.get("configurationItemStatus")

    if (event.get("eventLeftScope")
            or ci_status in ("ResourceDeleted", "ResourceDeletedNotRecorded")
            or resource_type != "AWS::EC2::SecurityGroup"):
        put_evaluation(resource_type, resource_id, "NOT_APPLICABLE",
                       "Resource not in scope.", result_token)
        return

    tags = extract_tags_from_config(config_item)
    if tags.get(WHITELIST_TAG_KEY, "").lower() == WHITELIST_TAG_VALUE:
        put_evaluation(resource_type, resource_id, "COMPLIANT",
                       f"Skipped: tagged {WHITELIST_TAG_KEY}={WHITELIST_TAG_VALUE}.",
                       result_token)
        return

    configuration = config_item.get("configuration") or {}
    if isinstance(configuration, str):
        configuration = json.loads(configuration)

    ip_permissions = configuration.get("ipPermissions", [])
    group_name     = configuration.get("groupName", resource_id)
    violations     = find_violations_config(ip_permissions)

    if not violations:
        put_evaluation(resource_type, resource_id, "COMPLIANT",
                       "No high-risk ports exposed to the internet.", result_token)
        return

    ports_summary = ", ".join(sorted({f"{v['port']} ({v['service']})" for v in violations}))
    remediated    = remediate(resource_id, violations) if AUTO_REMEDIATE else []

    write_audit_log(resource_id, group_name, violations, remediated, "AWS_Config")
    save_to_dynamodb(resource_id, group_name, violations, remediated, "AWS_Config")
    notify(resource_id, group_name, ports_summary, remediated)

    put_evaluation(resource_type, resource_id, "NON_COMPLIANT",
                   f"High-risk ports open: {ports_summary}", result_token)


# -----------------------------------------------------------------
# Handler: EventBridge (immediate - seconds latency)
# -----------------------------------------------------------------
def handle_eventbridge_event(event):
    detail = event.get("detail", {})
    if isinstance(detail, str):
        detail = json.loads(detail)

    event_name = detail.get("eventName", "")
    params     = detail.get("requestParameters") or {}
    if isinstance(params, str):
        params = json.loads(params)

    group_id = (params.get("groupId")
                or params.get("GroupId")
                or extract_group_id_from_response(detail)
                or "unknown")

    print(f"[EB] eventName={event_name}, groupId={group_id}")

    if not group_id or group_id == "unknown":
        print("[INFO] No groupId found in EventBridge event, skipping.")
        return

    # Fetch current SG details from EC2
    try:
        resp = ec2.describe_security_groups(GroupIds=[group_id])
        sg   = resp["SecurityGroups"][0]
    except Exception as exc:
        print(f"[WARN] Could not describe SG {group_id}: {exc}")
        return

    group_name     = sg.get("GroupName", group_id)
    ip_permissions = sg.get("IpPermissions", [])
    tags           = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}

    if tags.get(WHITELIST_TAG_KEY, "").lower() == WHITELIST_TAG_VALUE:
        print(f"[INFO] {group_id} is whitelisted, skipping.")
        return

    violations = find_violations_ec2(ip_permissions)
    if not violations:
        print(f"[INFO] {group_id} has no high-risk ports exposed.")
        return

    ports_summary = ", ".join(sorted({f"{v['port']} ({v['service']})" for v in violations}))
    remediated    = remediate(group_id, violations) if AUTO_REMEDIATE else []

    write_audit_log(group_id, group_name, violations, remediated, "EventBridge")
    save_to_dynamodb(group_id, group_name, violations, remediated, "EventBridge")
    notify(group_id, group_name, ports_summary, remediated)


def extract_group_id_from_response(detail):
    """Try to get groupId from responseElements for CreateSecurityGroup."""
    resp = detail.get("responseElements") or {}
    if isinstance(resp, str):
        resp = json.loads(resp)
    return resp.get("groupId") or resp.get("GroupId")


# -----------------------------------------------------------------
# Detection - Config format (camelCase keys)
# -----------------------------------------------------------------
def find_violations_config(ip_permissions):
    violations = []
    for perm in ip_permissions:
        if not isinstance(perm, dict):
            continue
        world_v4 = False
        world_v6 = False
        for r in perm.get("ipRanges", []):
            if isinstance(r, dict) and r.get("cidrIp") == "0.0.0.0/0":
                world_v4 = True
        for r in perm.get("ipv6Ranges", []):
            if isinstance(r, dict) and r.get("cidrIpv6") == "::/0":
                world_v6 = True
        if not (world_v4 or world_v6):
            continue

        protocol  = perm.get("ipProtocol")
        from_port = perm.get("fromPort")
        to_port   = perm.get("toPort")

        if protocol == "-1" or from_port is None or to_port is None:
            matched = list(HIGH_RISK_PORTS.items())
        else:
            matched = [(p, s) for p, s in HIGH_RISK_PORTS.items()
                       if int(from_port) <= p <= int(to_port)]

        for port, svc in matched:
            violations.append({
                "port": port, "service": svc, "protocol": protocol or "tcp",
                "from_port": from_port, "to_port": to_port,
                "world_v4": world_v4, "world_v6": world_v6,
            })
    return violations


# -----------------------------------------------------------------
# Detection - EC2 API format (PascalCase keys)
# -----------------------------------------------------------------
def find_violations_ec2(ip_permissions):
    violations = []
    for perm in ip_permissions:
        if not isinstance(perm, dict):
            continue
        world_v4 = False
        world_v6 = False
        for r in perm.get("IpRanges", []):
            if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
                world_v4 = True
        for r in perm.get("Ipv6Ranges", []):
            if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
                world_v6 = True
        if not (world_v4 or world_v6):
            continue

        protocol  = perm.get("IpProtocol")
        from_port = perm.get("FromPort")
        to_port   = perm.get("ToPort")

        if protocol == "-1" or from_port is None or to_port is None:
            matched = list(HIGH_RISK_PORTS.items())
        else:
            matched = [(p, s) for p, s in HIGH_RISK_PORTS.items()
                       if int(from_port) <= p <= int(to_port)]

        for port, svc in matched:
            violations.append({
                "port": port, "service": svc, "protocol": protocol or "tcp",
                "from_port": from_port, "to_port": to_port,
                "world_v4": world_v4, "world_v6": world_v6,
            })
    return violations


# -----------------------------------------------------------------
# Remediation
# -----------------------------------------------------------------
def remediate(group_id, violations):
    revoked = []
    seen    = set()
    for v in violations:
        key = (str(v["protocol"]), str(v["from_port"]), str(v["to_port"]),
               v["world_v4"], v["world_v6"])
        if key in seen:
            revoked.append((v["port"], v["service"]))
            continue
        seen.add(key)

        permission = {"IpProtocol": str(v["protocol"])}
        if str(v["protocol"]) != "-1" and v["from_port"] is not None:
            permission["FromPort"] = int(v["from_port"])
            permission["ToPort"]   = int(v["to_port"])
        if v["world_v4"]:
            permission["IpRanges"]   = [{"CidrIp": "0.0.0.0/0"}]
        if v["world_v6"]:
            permission["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]

        try:
            ec2.revoke_security_group_ingress(GroupId=group_id,
                                              IpPermissions=[permission])
            revoked.append((v["port"], v["service"]))
            print(f"[REMEDIATED] {group_id}: revoked port {v['port']}")
        except Exception as exc:
            print(f"[WARN] Revoke failed {group_id} port {v['port']}: {exc}")
    return revoked


# -----------------------------------------------------------------
# DynamoDB
# -----------------------------------------------------------------
def save_to_dynamodb(group_id, group_name, violations, remediated, source):
    if not DYNAMODB_TABLE:
        print("[INFO] DYNAMODB_TABLE not set; skipping.")
        return
    try:
        table   = dynamodb.Table(DYNAMODB_TABLE)
        ts      = datetime.now(timezone.utc).isoformat()
        exposed = ", ".join(sorted({f"{v['port']}/{v['service']}" for v in violations}))
        closed  = ", ".join(f"{p}/{s}" for p, s in remediated) or "none"
        table.put_item(Item={
            "alert_id":            str(uuid.uuid4()),
            "timestamp":           ts,
            "security_group_id":   group_id,
            "security_group_name": group_name,
            "exposed_ports":       exposed,
            "ports_closed":        closed,
            "action":              "REMEDIATED" if remediated else "DETECTED",
            "source":              source,
        })
        print(f"[DYNAMODB] Saved alert for {group_id}")
    except Exception as exc:
        print(f"[WARN] DynamoDB write failed: {exc}")


# -----------------------------------------------------------------
# S3 CSV Audit Log
# -----------------------------------------------------------------
def write_audit_log(group_id, group_name, violations, remediated, source):
    if not AUDIT_BUCKET:
        print("[INFO] AUDIT_BUCKET not set; skipping.")
        return
    exposed = "; ".join(sorted({f"{v['port']}/{v['service']}" for v in violations}))
    closed  = "; ".join(f"{p}/{s}" for p, s in remediated) or "none"
    row     = [datetime.now(timezone.utc).isoformat(), group_id, group_name,
               exposed, closed, "REMEDIATED" if remediated else "DETECTED", source]
    existing = ""
    try:
        obj      = s3.get_object(Bucket=AUDIT_BUCKET, Key=AUDIT_KEY)
        existing = obj["Body"].read().decode("utf-8")
    except Exception:
        pass

    buf = io.StringIO()
    w   = csv.writer(buf)
    if not existing:
        w.writerow(CSV_HEADER)
    w.writerow(row)
    s3.put_object(Bucket=AUDIT_BUCKET, Key=AUDIT_KEY,
                  Body=(existing + buf.getvalue()).encode("utf-8"),
                  ContentType="text/csv")
    print(f"[S3] Audit log updated for {group_id}")


# -----------------------------------------------------------------
# SNS Notification  (improved email formatting)
# -----------------------------------------------------------------
def notify(group_id, group_name, ports_summary, remediated):
    if not SNS_TOPIC_ARN:
        print("[INFO] SNS_TOPIC_ARN not set; skipping.")
        return

    action  = "AUTO-REMEDIATED" if remediated else "DETECTED (no auto-remediation)"
    status  = "RESOLVED" if remediated else "ACTION REQUIRED"
    closed  = ", ".join(f"{p} ({s})" for p, s in remediated) or "None"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = (
        "[RESOLVED] High-Risk Port Auto-Remediated"
        if remediated else
        "[ACTION REQUIRED] High-Risk Port Exposed to Internet"
    )

    if remediated:
        next_step = ("No action needed. The exposed port(s) were automatically "
                     "closed. Review the audit log if this was unexpected.")
    else:
        next_step = ("Manual action required: review and close the exposed port(s) "
                     "in the EC2 console, or restrict the source to a trusted IP.")

    message = (
        "==================================================\n"
        "  AWS CLOUD SECURITY ALERT\n"
        "  High-Risk Port Exposure Detected\n"
        "==================================================\n\n"
        f"  Status          : {status}\n"
        f"  Severity        : HIGH\n"
        f"  Action Taken    : {action}\n\n"
        "--------------------------------------------------\n"
        "  RESOURCE DETAILS\n"
        "--------------------------------------------------\n"
        f"  Security Group  : {group_name}\n"
        f"  Group ID        : {group_id}\n"
        f"  Exposed Ports   : {ports_summary}\n"
        f"  Ports Closed    : {closed}\n"
        f"  Time            : {now_utc}\n\n"
        "--------------------------------------------------\n"
        "  NEXT STEP\n"
        "--------------------------------------------------\n"
        f"  {next_step}\n\n"
        "==================================================\n"
        "  Automated by AWS Cloud Misconfiguration\n"
        "  Auto-Remediation System\n"
        "==================================================\n"
    )

    sns.publish(TopicArn=SNS_TOPIC_ARN,
                Subject=subject,
                Message=message)
    print(f"[DONE] Alert processed and notification sent for {group_id}")


# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------
def extract_tags_from_config(config_item):
    tags = {}
    raw  = config_item.get("tags")
    if isinstance(raw, dict):
        tags.update(raw)
    cfg = config_item.get("configuration") or {}
    if isinstance(cfg, str):
        cfg = json.loads(cfg)
    for t in cfg.get("tagSet", []):
        if isinstance(t, dict) and "key" in t:
            tags[t["key"]] = t.get("value", "")
    return tags


def put_evaluation(resource_type, resource_id, compliance, annotation, result_token):
    try:
        config_client.put_evaluations(
            Evaluations=[{
                "ComplianceResourceType": resource_type or "AWS::EC2::SecurityGroup",
                "ComplianceResourceId":   resource_id   or "unknown",
                "ComplianceType":         compliance,
                "Annotation":             annotation[:256],
                "OrderingTimestamp":      datetime.now(timezone.utc),
            }],
            ResultToken=result_token,
        )
    except Exception as exc:
        print(f"[WARN] put_evaluations failed: {exc}")
