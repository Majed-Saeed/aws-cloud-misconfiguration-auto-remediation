import boto3
import json
import os
from datetime import datetime

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    """
    Auto-remediation for S3 bucket public read access.
    Triggered by AWS Config compliance change events.
    """
    
    try:
        # Extract bucket name from Config event
        config_item = json.loads(event['configurationItem'])
        bucket_name = config_item['resourceName']
        
        print(f"[INFO] Processing bucket: {bucket_name}")
        
        # Block public access
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        print(f"[SUCCESS] Public access blocked for {bucket_name}")
        
        # Send SNS notification
        message = f"""
Cloud Misconfiguration Auto-Remediation Report
===============================================
Timestamp: {datetime.now().isoformat()}
Resource Type: S3 Bucket
Resource Name: {bucket_name}
Rule: s3-bucket-public-read-prohibited
Action: Block Public Access
Status: ✅ REMEDIATED SUCCESSFULLY

The bucket is now private and no longer publicly accessible.
"""
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'[REMEDIATED] S3 bucket {bucket_name} is now private',
            Message=message
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Remediation successful',
                'bucket': bucket_name
            })
        }
        
    except Exception as e:
        error_msg = f"[ERROR] Remediation failed: {str(e)}"
        print(error_msg)
        
        # Send failure notification
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='[FAILED] S3 remediation failed',
            Message=f"Error: {error_msg}\n\nEvent: {json.dumps(event, indent=2)}"
        )
        
        raise
