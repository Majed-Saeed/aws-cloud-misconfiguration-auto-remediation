"""
High-Risk Port Exposure Detection & Auto-Remediation
with Risk Scoring Engine (FYP enhancement)

Supports : AWS Config events + EventBridge (CloudTrail) events
Outputs  : SNS alert, S3 CSV audit log, DynamoDB record
Adds     : Risk Score (0-100) + Risk Level (HIGH/MEDIUM/LOW)
           Evasion-resistant CIDR breadth analysis
           Evasion-aware remediation (revokes the ACTUAL exposing CIDR)
"""

import os
import io
import csv
import json
import uuid
import ipaddress
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

# Evasion detection: also flag wide CIDRs (e.g. 0.0.0.0/1), not only exact 0.0.0.0/0.
# Set to "false" to reproduce the naive baseline for the before/after experiment.
EVASION_DETECTION = os.environ.get("EVASION_DETECTION", "true").lower() == "true"

# A CIDR with a prefix length <= this is treated as internet-exposed.
# /8 means anything covering 16 million+ addresses counts as "wide open".
WIDE_CIDR_PREFIX_V4 = int(os.environ.get("WIDE_CIDR_PREFIX_V4", "8"))
WIDE_CIDR_PREFIX_V6 = int(os.environ.get("WIDE_CIDR_PREFIX_V6", "32"))

CSV_HEADER = ["timestamp_utc", "security_group_id", "security_group_name",
              "exposed_ports", "ports_closed", "risk_score", "risk_level",
              "action", "source"]

config_client = boto3.client("config")
ec2           = boto3.client("ec2")
sns           = boto3.client("sns")
s3            = boto3.client("s3")
dynamodb      = boto3.resource("dynamodb")


# =================================================================
# RISK SCORING ENGINE  (FYP contribution)
# =================================================================
#
# A finding's risk score (0-100) is the weighted sum of four factors:
#
#   1. Port sensitivity     (max 40) - how dangerous the service is
#   2. Exposure breadth     (max 30) - how many IPs can reach it
#   3. Port-range width     (max 20) - how many ports were opened at once
#   4. Protocol openness    (max 10) - whether ALL protocols were allowed
#
# Risk level:  HIGH >= 70,  MEDIUM >= 40,  LOW < 40
# -----------------------------------------------------------------

PORT_RISK_WEIGHTS = {
    3389: 40,   # RDP    - prime ransomware/brute-force target
    22:   38,   # SSH    - full remote shell access
    23:   36,   # Telnet - remote access, unencrypted
    5900: 34,   # VNC    - remote desktop, often weak auth
    1433: 28,   # SQL Server
    3306: 28,   # MySQL
    5432: 28,   # PostgreSQL
}
DEFAULT_PORT_WEIGHT = 25

HIGH_THRESHOLD   = 70
MEDIUM_THRESHOLD = 40


def cidr_breadth_points(prefix_len, is_v6):
    """
    Exposure breadth score (max 30) based on how wide the CIDR is.
    Smaller prefix length = more IP addresses exposed = higher risk.

    Evasion-resistant: 0.0.0.0/1 (half the internet) scores as high as
    0.0.0.0/0, even though it is not the exact string AWS rules look for.
    """
    if is_v6:
        if prefix_len <= 3:    return 30
        if prefix_len <= 16:   return 22
        if prefix_len <= 32:   return 14
        if prefix_len <= 64:   return 7
        return 3

    if prefix_len <= 4:    return 30   # 0.0.0.0/0 to /4 - whole-internet class
    if prefix_len <= 8:    return 22   # /5 - /8   - 16M+ addresses
    if prefix_len <= 16:   return 14   # /9 - /16  - 65k+ addresses
    if prefix_len <= 24:   return 7    # /17 - /24 - up to 256 addresses
    return 3                           # /25+      - very narrow


def port_range_points(from_port, to_port, protocol):
    """Port-range width score (max 20). Opening many ports at once is worse."""
    if str(protocol) == "-1" or from_port is None or to_port is None:
        return 20
    try:
        span = int(to_port) - int(from_port) + 1
    except (TypeError, ValueError):
        return 5
    if span <= 1:    return 5
    if span <= 10:   return 10
    if span <= 100:  return 14
    return 18


def protocol_points(protocol):
    """Protocol openness score (max 10). 'All traffic' (-1) is riskiest."""
    return 10 if str(protocol) == "-1" else 0


def calculate_risk_score(violation):
    """Compute (score, level, breakdown) for one finding."""
    port      = violation.get("port")
    protocol  = violation.get("protocol")
    from_port = violation.get("from_port")
    to_port   = violation.get("to_port")
    prefix    = violation.get("widest_prefix")
    is_v6     = violation.get("widest_is_v6", False)

    port_pts    = PORT_RISK_WEIGHTS.get(port, DEFAULT_PORT_WEIGHT)
    breadth_pts = cidr_breadth_points(prefix if prefix is not None else 0, is_v6)
    range_pts   = port_range_points(from_port, to_port, protocol)
    proto_pts   = protocol_points(protocol)

    score = max(0, min(100, port_pts + breadth_pts + range_pts + proto_pts))

    if score >= HIGH_THRESHOLD:
        level = "HIGH"
    elif score >= MEDIUM_THRESHOLD:
        level = "MEDIUM"
    else:
        level = "LOW"

    breakdown = {
        "port_sensitivity": port_pts,
        "exposure_breadth": breadth_pts,
        "port_range_width": range_pts,
        "protocol_openness": proto_pts,
    }
    return score, level, breakdown


def summarise_group_risk(violations):
    """Annotate each violation with its score/level; return worst (score, level)."""
    overall_score = 0
    overall_level = "LOW"
    for v in violations:
        score, level, breakdown = calculate_risk_score(v)
        v["risk_score"] = score
        v["risk_level"] = level
        v["risk_breakdown"] = breakdown
        if score > overall_score:
            overall_score = score
            overall_level = level
    return overall_score, overall_level


# -----------------------------------------------------------------
# CIDR helpers (evasion-resistant exposure analysis)
# -----------------------------------------------------------------
def cidr_prefix_len(cidr):
    """Return (prefix_len, is_v6) for a CIDR string, or None if invalid."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.prefixlen, (net.version == 6)
    except ValueError:
        return None


def is_internet_exposing(cidr):
    """
    True if this CIDR exposes the resource to the internet.
    Always true for exact 0.0.0.0/0 or ::/0 (baseline behaviour).
    If EVASION_DETECTION is on, also true for wide CIDRs (e.g. /1, /8).
    """
    if cidr in ("0.0.0.0/0", "::/0"):
        return True
    if not EVASION_DETECTION:
        return False
    parsed = cidr_prefix_len(cidr)
    if parsed is None:
        return False
    prefix_len, is_v6 = parsed
    threshold = WIDE_CIDR_PREFIX_V6 if is_v6 else WIDE_CIDR_PREFIX_V4
    return prefix_len <= threshold


# -----------------------------------------------------------------
# Entry point - detects event source and routes
# -----------------------------------------------------------------
def lambda_handler(event, context):
    print("[EVENT] Received:", json.dumps(event, default=str)[:2000])

    if isinstance(event, str):
        try:
            event = json.loads(event)
        except (ValueError, TypeError):
            print("[WARN] Event is a non-JSON string, skipping.")
            return

    if not isinstance(event, dict):
        print("[WARN] Event is not a dict, skipping.")
        return

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

    overall_score, overall_level = summarise_group_risk(violations)
    ports_summary = ", ".join(sorted({f"{v['port']} ({v['service']})" for v in violations}))
    remediated    = remediate(resource_id, violations) if AUTO_REMEDIATE else []

    write_audit_log(resource_id, group_name, violations, remediated,
                    overall_score, overall_level, "AWS_Config")
    save_to_dynamodb(resource_id, group_name, violations, remediated,
                     overall_score, overall_level, "AWS_Config")
    notify(resource_id, group_name, ports_summary, violations, remediated,
           overall_score, overall_level)

    put_evaluation(resource_type, resource_id, "NON_COMPLIANT",
                   f"High-risk ports open: {ports_summary} "
                   f"[Risk {overall_score}/100 {overall_level}]", result_token)


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

    overall_score, overall_level = summarise_group_risk(violations)
    ports_summary = ", ".join(sorted({f"{v['port']} ({v['service']})" for v in violations}))
    remediated    = remediate(group_id, violations) if AUTO_REMEDIATE else []

    write_audit_log(group_id, group_name, violations, remediated,
                    overall_score, overall_level, "EventBridge")
    save_to_dynamodb(group_id, group_name, violations, remediated,
                     overall_score, overall_level, "EventBridge")
    notify(group_id, group_name, ports_summary, violations, remediated,
           overall_score, overall_level)


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

        v4_cidrs, v6_cidrs, prefixes = [], [], []
        for r in perm.get("ipRanges", []):
            if isinstance(r, dict):
                cidr = r.get("cidrIp")
                if cidr and is_internet_exposing(cidr) and cidr not in v4_cidrs:
                    v4_cidrs.append(cidr)
                    p = cidr_prefix_len(cidr)
                    if p:
                        prefixes.append(p)
        for r in perm.get("ipv6Ranges", []):
            if isinstance(r, dict):
                cidr = r.get("cidrIpv6")
                if cidr and is_internet_exposing(cidr) and cidr not in v6_cidrs:
                    v6_cidrs.append(cidr)
                    p = cidr_prefix_len(cidr)
                    if p:
                        prefixes.append(p)

        if not (v4_cidrs or v6_cidrs) or not prefixes:
            continue

        widest_prefix, widest_is_v6 = min(prefixes, key=lambda t: t[0])
        _append_violations(violations, perm.get("ipProtocol"),
                           perm.get("fromPort"), perm.get("toPort"),
                           v4_cidrs, v6_cidrs, widest_prefix, widest_is_v6)
    return violations


# -----------------------------------------------------------------
# Detection - EC2 API format (PascalCase keys)
# -----------------------------------------------------------------
def find_violations_ec2(ip_permissions):
    violations = []
    for perm in ip_permissions:
        if not isinstance(perm, dict):
            continue

        v4_cidrs, v6_cidrs, prefixes = [], [], []
        for r in perm.get("IpRanges", []):
            if isinstance(r, dict):
                cidr = r.get("CidrIp")
                if cidr and is_internet_exposing(cidr) and cidr not in v4_cidrs:
                    v4_cidrs.append(cidr)
                    p = cidr_prefix_len(cidr)
                    if p:
                        prefixes.append(p)
        for r in perm.get("Ipv6Ranges", []):
            if isinstance(r, dict):
                cidr = r.get("CidrIpv6")
                if cidr and is_internet_exposing(cidr) and cidr not in v6_cidrs:
                    v6_cidrs.append(cidr)
                    p = cidr_prefix_len(cidr)
                    if p:
                        prefixes.append(p)

        if not (v4_cidrs or v6_cidrs) or not prefixes:
            continue

        widest_prefix, widest_is_v6 = min(prefixes, key=lambda t: t[0])
        _append_violations(violations, perm.get("IpProtocol"),
                           perm.get("FromPort"), perm.get("ToPort"),
                           v4_cidrs, v6_cidrs, widest_prefix, widest_is_v6)
    return violations


def _append_violations(violations, protocol, from_port, to_port,
                       v4_cidrs, v6_cidrs, widest_prefix, widest_is_v6):
    """Expand one permission into per-port violation records.
    The ACTUAL exposing CIDRs are carried through so remediation can
    revoke the exact rule (this is what fixes evasion remediation)."""
    if str(protocol) == "-1" or from_port is None or to_port is None:
        matched = list(HIGH_RISK_PORTS.items())
    else:
        try:
            matched = [(p, s) for p, s in HIGH_RISK_PORTS.items()
                       if int(from_port) <= p <= int(to_port)]
        except (TypeError, ValueError):
            matched = []

    for port, svc in matched:
        violations.append({
            "port": port, "service": svc, "protocol": protocol or "tcp",
            "from_port": from_port, "to_port": to_port,
            "v4_cidrs": list(v4_cidrs), "v6_cidrs": list(v6_cidrs),
            "widest_prefix": widest_prefix, "widest_is_v6": widest_is_v6,
        })


# -----------------------------------------------------------------
# Remediation  (revokes the ACTUAL exposing CIDR - evasion-aware)
# -----------------------------------------------------------------
def remediate(group_id, violations):
    revoked = []
    seen    = set()
    for v in violations:
        key = (str(v["protocol"]), str(v["from_port"]), str(v["to_port"]),
               tuple(sorted(v["v4_cidrs"])), tuple(sorted(v["v6_cidrs"])))
        if key in seen:
            # Same underlying rule already revoked; still report this port closed.
            revoked.append((v["port"], v["service"]))
            continue
        seen.add(key)

        permission = {"IpProtocol": str(v["protocol"])}
        if str(v["protocol"]) != "-1" and v["from_port"] is not None:
            permission["FromPort"] = int(v["from_port"])
            permission["ToPort"]   = int(v["to_port"])
        if v["v4_cidrs"]:
            permission["IpRanges"]   = [{"CidrIp": c}    for c in v["v4_cidrs"]]
        if v["v6_cidrs"]:
            permission["Ipv6Ranges"] = [{"CidrIpv6": c}  for c in v["v6_cidrs"]]

        try:
            ec2.revoke_security_group_ingress(GroupId=group_id,
                                              IpPermissions=[permission])
            revoked.append((v["port"], v["service"]))
            closed_cidrs = ", ".join(v["v4_cidrs"] + v["v6_cidrs"])
            print(f"[REMEDIATED] {group_id}: revoked port {v['port']} "
                  f"on {closed_cidrs}")
        except Exception as exc:
            print(f"[WARN] Revoke failed {group_id} port {v['port']}: {exc}")
    return revoked


# -----------------------------------------------------------------
# DynamoDB  (stores risk_score + risk_level)
# -----------------------------------------------------------------
def save_to_dynamodb(group_id, group_name, violations, remediated,
                     risk_score, risk_level, source):
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
            "risk_score":          risk_score,
            "risk_level":          risk_level,
            "action":              "REMEDIATED" if remediated else "DETECTED",
            "source":              source,
        })
        print(f"[DYNAMODB] Saved alert for {group_id} "
              f"(risk {risk_score}/100 {risk_level})")
    except Exception as exc:
        print(f"[WARN] DynamoDB write failed: {exc}")


# -----------------------------------------------------------------
# S3 CSV Audit Log  (includes risk_score + risk_level columns)
# -----------------------------------------------------------------
def write_audit_log(group_id, group_name, violations, remediated,
                    risk_score, risk_level, source):
    if not AUDIT_BUCKET:
        print("[INFO] AUDIT_BUCKET not set; skipping.")
        return
    exposed = "; ".join(sorted({f"{v['port']}/{v['service']}" for v in violations}))
    closed  = "; ".join(f"{p}/{s}" for p, s in remediated) or "none"
    row     = [datetime.now(timezone.utc).isoformat(), group_id, group_name,
               exposed, closed, risk_score, risk_level,
               "REMEDIATED" if remediated else "DETECTED", source]
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
    try:
        s3.put_object(Bucket=AUDIT_BUCKET, Key=AUDIT_KEY,
                      Body=(existing + buf.getvalue()).encode("utf-8"),
                      ContentType="text/csv")
        print(f"[S3] Audit log updated for {group_id}")
    except Exception as exc:
        print(f"[WARN] S3 audit write failed: {exc}")


# -----------------------------------------------------------------
# SNS Notification  (shows risk score, level and breakdown)
# -----------------------------------------------------------------
def notify(group_id, group_name, ports_summary, violations, remediated,
           risk_score, risk_level):
    if not SNS_TOPIC_ARN:
        print("[INFO] SNS_TOPIC_ARN not set; skipping.")
        return

    action  = "AUTO-REMEDIATED" if remediated else "DETECTED (no auto-remediation)"
    status  = "RESOLVED" if remediated else "ACTION REQUIRED"
    closed  = ", ".join(f"{p} ({s})" for p, s in remediated) or "None"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    level_icon = {"HIGH": "[!!!] HIGH", "MEDIUM": "[!!] MEDIUM", "LOW": "[!] LOW"}
    risk_line  = level_icon.get(risk_level, risk_level)

    subject = (
        f"[{risk_level}] High-Risk Port "
        + ("Auto-Remediated" if remediated else "Exposed to Internet")
    )

    worst = max(violations, key=lambda v: v.get("risk_score", 0)) if violations else {}
    bd    = worst.get("risk_breakdown", {})

    message = (
        "==================================================\n"
        "  AWS CLOUD SECURITY ALERT\n"
        "  High-Risk Port Exposure Detected\n"
        "==================================================\n\n"
        f"  RISK SCORE      : {risk_score} / 100\n"
        f"  RISK LEVEL      : {risk_line}\n"
        f"  STATUS          : {status}\n"
        f"  ACTION TAKEN    : {action}\n\n"
        "--------------------------------------------------\n"
        "  RESOURCE DETAILS\n"
        "--------------------------------------------------\n"
        f"  Security Group  : {group_name}\n"
        f"  Group ID        : {group_id}\n"
        f"  Exposed Ports   : {ports_summary}\n"
        f"  Ports Closed    : {closed}\n"
        f"  Time            : {now_utc}\n\n"
        "--------------------------------------------------\n"
        "  RISK SCORE BREAKDOWN (worst finding)\n"
        "--------------------------------------------------\n"
        f"  Port sensitivity  : {bd.get('port_sensitivity', 0)} / 40\n"
        f"  Exposure breadth  : {bd.get('exposure_breadth', 0)} / 30\n"
        f"  Port-range width  : {bd.get('port_range_width', 0)} / 20\n"
        f"  Protocol openness : {bd.get('protocol_openness', 0)} / 10\n\n"
        "==================================================\n"
        "  Automated by AWS Cloud Misconfiguration\n"
        "  Auto-Remediation System\n"
        "==================================================\n"
    )

    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
        print(f"[DONE] Alert sent for {group_id} (risk {risk_score}/100 {risk_level})")
    except Exception as exc:
        print(f"[WARN] SNS publish failed: {exc}")


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
