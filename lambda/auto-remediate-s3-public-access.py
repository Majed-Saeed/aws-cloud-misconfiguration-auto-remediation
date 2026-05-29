import boto3
import json
import os
import uuid
from datetime import datetime

s3 = boto3.client('s3')
ec2 = boto3.client('ec2')
iam = boto3.client('iam')
rds = boto3.client('rds')
sns = boto3.client('sns')
db = boto3.resource('dynamodb')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE']


def lambda_handler(event, context):
    print(json.dumps(event))

    rule = event['detail']['configRuleName']
    resource_id = event['detail']['resourceId']
    resource_type = event['detail']['resourceType']

    result = remediate(rule, resource_id, resource_type)

    log_to_dynamodb(rule, resource_id, resource_type, result)
    send_notification(rule, resource_id, result)

    return result


def remediate(rule, resource_id, resource_type):

    if 's3-bucket-public-read' in rule or 's3-bucket-public-write' in rule:

        s3.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        try:
            s3.delete_bucket_policy(Bucket=resource_id)
        except Exception as e:
            print("S3 POLICY DELETE ERROR:", str(e))

        return {
            "status": "REMEDIATED",
            "action": "S3 public access blocked + policy deleted"
        }

    elif rule == 'restricted-ssh':

        try:
            response = ec2.revoke_security_group_ingress(
                GroupId=resource_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [
                            {'CidrIp': '0.0.0.0/0'}
                        ]
                    }
                ]
            )

            print("SSH REMOVED")
            print(response)

            return {
                "status": "REMEDIATED",
                "action": "SSH port 22 closed"
            }

        except Exception as e:

            print("SSH ERROR:", str(e))

            return {
                "status": "FAILED",
                "action": str(e)
            }

    elif rule == 'restricted-rdp':

        try:
            response = ec2.revoke_security_group_ingress(
                GroupId=resource_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 3389,
                        'ToPort': 3389,
                        'IpRanges': [
                            {'CidrIp': '0.0.0.0/0'}
                        ]
                    }
                ]
            )

            print("RDP REMOVED")
            print(response)

            return {
                "status": "REMEDIATED",
                "action": "RDP port 3389 closed"
            }

        except Exception as e:

            print("RDP ERROR:", str(e))

            return {
                "status": "FAILED",
                "action": str(e)
            }

    elif rule == 'rds-instance-public-access-check':

        try:
            rds.modify_db_instance(
                DBInstanceIdentifier=resource_id,
                PubliclyAccessible=False,
                ApplyImmediately=True
            )

            return {
                "status": "REMEDIATED",
                "action": "RDS public access disabled"
            }

        except Exception as e:

            print("RDS ERROR:", str(e))

            return {
                "status": "FAILED",
                "action": str(e)
            }

    elif rule in ['iam-user-mfa-enabled', 'root-account-mfa-enabled']:

        return {
            "status": "ALERT_ONLY",
            "action": "MFA not enabled — manual fix required"
        }

    else:

        return {
            "status": "NO_ACTION",
            "action": f"No remediation for rule: {rule}"
        }


def log_to_dynamodb(rule, resource_id, resource_type, result):

    table = db.Table(DYNAMODB_TABLE)

    table.put_item(
        Item={
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'rule': rule,
            'resource_id': resource_id,
            'resource_type': resource_type,
            'status': result['status'],
            'action': result['action']
        }
    )


def send_notification(rule, resource_id, result):

    status_emoji = "✅" if result['status'] == "REMEDIATED" else "⚠️"

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"{status_emoji} [{result['status']}] {rule}",
        Message=f"""
Cloud Misconfiguration Auto-Remediation Report
===============================================
Timestamp   : {datetime.utcnow().isoformat()}
Rule        : {rule}
Resource    : {resource_id}
Action      : {result['action']}
Status      : {result['status']}
================================================
Secured automatically by FYP Remediation System.
"""
    )
