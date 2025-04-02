# AWS WAF to Elastic Stack Integration

This Terraform project creates the necessary AWS infrastructure to collect AWS WAF logs and send them to Elastic Stack using Elastic Agent.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│             │     │             │     │             │     │             │
│  WAF WebACL ├────►│  S3 Bucket  ├────►│  SQS Queue  ├────►│ Elastic Agent│
│             │     │             │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                                                       ▲
       │                                                       │
       │            ┌─────────────┐                            │
       └───────────►│ API Gateway │                            │
                    │             │                            │
                    └─────────────┘                            │
                                                               │
                    ┌─────────────┐                            │
                    │             │                            │
                    │  EC2 Host   ├───────────────────────────┘
                    │             │
                    └─────────────┘
```

## Resources Created

- **AWS WAF WebACL**: A Web Application Firewall to protect the API Gateway
- **API Gateway**: A simple API to test the WAF
- **S3 Bucket**: To store the WAF logs
- **SQS Queue**: To receive notifications when new logs are uploaded to S3
- **EC2 Instance**: To run the Elastic Agent (not installed by this Terraform)
- **IAM Role**: To allow the EC2 instance to access the S3 bucket and SQS queue

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.0.0
- SSH key pair for EC2 instance access

## Usage

1. Clone this repository
2. Create a `terraform.tfvars` file based on the example
3. Initialize Terraform
   ```
   terraform init
   ```
4. Plan and apply the changes
   ```
   terraform plan
   terraform apply
   ```
5. After deployment, you can test the WAF with the provided test script
   ```
   ./test-waf.sh $(terraform output -raw waf_protected_url)
   ```
6. To SSH into the EC2 instance:
   ```
   ssh ec2-user@$(terraform output -raw ec2_public_ip)
   ```

## Elastic Agent Configuration

After the infrastructure is deployed, you'll need to install Elastic Agent on the EC2 instance. The agent will need to be configured with the `aws-s3` input to collect logs from the SQS queue.

Sample configuration:

```yaml
- type: aws-s3
  queue_url: ${sqs_queue_url}
  expand_event_list_from_field: Records
```

Replace `${sqs_queue_url}` with the SQS queue URL from the Terraform output.

## Testing

You can test the WAF with the provided shell script:

```
./test-waf.sh $(terraform output -raw waf_protected_url)
```

This will send several test requests to the API Gateway, including some that should trigger WAF rules.

There's also a Python test script that can be used to generate more traffic and verify the logs:

```
pip install -r requirements.txt
python test_waf.py
```

## Cleanup

To destroy all created resources:

```
terraform destroy
```

Note: The S3 bucket has `force_destroy = true` set, so it will be deleted even if it contains logs.

## IAM Permissions

The EC2 instance has the following IAM permissions:
- `s3:GetObject`, `s3:ListBucket` - To access logs in the S3 bucket
- `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`, `sqs:ChangeMessageVisibility` - To process SQS messages
- `ec2:DescribeTags` - To describe EC2 instance tags