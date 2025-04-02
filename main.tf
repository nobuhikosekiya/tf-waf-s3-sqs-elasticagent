# -----------------------------------------------------
# Data sources
# -----------------------------------------------------
data "aws_caller_identity" "current" {}

# Use current public IP for security group ingress
data "http" "myip" {
  url = "https://api.ipify.org"
}

# Get the public SSH key from the specified path
data "local_file" "ssh_public_key" {
  filename = pathexpand("~/.ssh/id_rsa.pub")
}

# -----------------------------------------------------
# IAM Role for EC2 to access S3 and SQS
# -----------------------------------------------------
resource "aws_iam_role" "ec2_role" {
  name = "${var.resource_prefix}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "s3_sqs_policy" {
  name        = "${var.resource_prefix}-s3-sqs-policy"
  description = "Policy to allow EC2 to access S3 and SQS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.waf_logs.arn,
          "${aws_s3_bucket.waf_logs.arn}/*"
        ]
      },
      {
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ]
        Effect   = "Allow"
        Resource = aws_sqs_queue.waf_logs_queue.arn
      },
      {
        Action = [
          "ec2:DescribeTags"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_sqs_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_sqs_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.resource_prefix}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# -----------------------------------------------------
# S3 Bucket for WAF Logs
# -----------------------------------------------------
# IMPORTANT: For direct WAF logging to S3, the bucket name MUST start with "aws-waf-logs-"
# This is a requirement enforced by AWS and cannot be bypassed.
resource "aws_s3_bucket" "waf_logs" {
  bucket = "aws-waf-logs-${var.resource_prefix}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_notification" "waf_logs_notification" {
  bucket = aws_s3_bucket.waf_logs.id

  queue {
    queue_arn     = aws_sqs_queue.waf_logs_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".gz"
  }

  depends_on = [aws_sqs_queue_policy.waf_logs_queue_policy]
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs_lifecycle" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "log-expiration"
    status = "Enabled"

    filter {
      prefix = "" # Empty prefix matches all objects
    }

    expiration {
      days = var.s3_log_expiration_days
    }
  }
}

# -----------------------------------------------------
# SQS Queue for S3 Notifications
# -----------------------------------------------------
resource "aws_sqs_queue" "waf_logs_queue" {
  name                      = "${var.resource_prefix}-logs-queue"
  message_retention_seconds = 1209600 # 14 days
  visibility_timeout_seconds = 300
}

resource "aws_sqs_queue_policy" "waf_logs_queue_policy" {
  queue_url = aws_sqs_queue.waf_logs_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.waf_logs_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.waf_logs.arn
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------
# WAF WebACL
# -----------------------------------------------------
resource "aws_wafv2_web_acl" "waf_acl" {
  name        = "${var.resource_prefix}-web-acl"
  description = "WAF WebACL for logging demonstration"
  scope       = var.waf_scope

  default_action {
    allow {}
  }

  # Example rule to block requests from specific IPs
  rule {
    name     = "block-test-ips"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockTestIPs"
      sampled_requests_enabled   = true
    }
  }

  # Example rule to detect SQL injection
  rule {
    name     = "detect-sql-injection"
    priority = 2

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          all_query_arguments {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "DetectSQLInjection"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "WAFWebACL"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "${var.resource_prefix}-blocked-ips"
  description        = "IP set for testing WAF blocking"
  scope              = var.waf_scope
  ip_address_version = "IPV4"
  
  # This is just for demonstration - includes the localhost IP to test blocking
  addresses = ["127.0.0.1/32"]
}

# -----------------------------------------------------
# Simple API Gateway for WAF demo
# -----------------------------------------------------
resource "aws_api_gateway_rest_api" "demo_api" {
  name        = "${var.resource_prefix}-demo-api"
  description = "Demo API for WAF testing"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "demo_resource" {
  rest_api_id = aws_api_gateway_rest_api.demo_api.id
  parent_id   = aws_api_gateway_rest_api.demo_api.root_resource_id
  path_part   = "test"
}

resource "aws_api_gateway_method" "demo_method" {
  rest_api_id   = aws_api_gateway_rest_api.demo_api.id
  resource_id   = aws_api_gateway_resource.demo_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "demo_integration" {
  rest_api_id = aws_api_gateway_rest_api.demo_api.id
  resource_id = aws_api_gateway_resource.demo_resource.id
  http_method = aws_api_gateway_method.demo_method.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }
}

resource "aws_api_gateway_method_response" "demo_response_200" {
  rest_api_id = aws_api_gateway_rest_api.demo_api.id
  resource_id = aws_api_gateway_resource.demo_resource.id
  http_method = aws_api_gateway_method.demo_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "demo_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.demo_api.id
  resource_id = aws_api_gateway_resource.demo_resource.id
  http_method = aws_api_gateway_method.demo_method.http_method
  status_code = aws_api_gateway_method_response.demo_response_200.status_code

  response_templates = {
    "application/json" = jsonencode({
      message = "This is a test endpoint for WAF demo"
    })
  }
}

resource "aws_api_gateway_deployment" "demo_deployment" {
  depends_on = [
    aws_api_gateway_integration.demo_integration,
    aws_api_gateway_integration_response.demo_integration_response
  ]

  rest_api_id = aws_api_gateway_rest_api.demo_api.id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_web_acl_association" "demo_association" {
  resource_arn = aws_api_gateway_stage.demo_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.waf_acl.arn
}

resource "aws_api_gateway_stage" "demo_stage" {
  deployment_id = aws_api_gateway_deployment.demo_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.demo_api.id
  stage_name    = "prod"
}

# -----------------------------------------------------
# WAF Logging S3 Bucket Policy
# -----------------------------------------------------
resource "aws_s3_bucket_policy" "waf_logs_bucket_policy" {
  bucket = aws_s3_bucket.waf_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.waf_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.waf_logs.arn
      }
    ]
  })
}

# -----------------------------------------------------
# Configure WAF Logging to S3
# -----------------------------------------------------
# For direct WAF logging to S3, we must use the bucket ARN as the log_destination_configs
# The bucket must start with "aws-waf-logs-" for this to work
resource "aws_wafv2_web_acl_logging_configuration" "waf_logging" {
  log_destination_configs = [aws_s3_bucket.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.waf_acl.arn
  
  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }
  }

  depends_on = [aws_s3_bucket_policy.waf_logs_bucket_policy]
}

# -----------------------------------------------------
# SSH Key Pair
# -----------------------------------------------------
resource "aws_key_pair" "ssh_key" {
  key_name   = "${var.resource_prefix}-key"
  public_key = data.local_file.ssh_public_key.content
}

# -----------------------------------------------------
# Security Group for EC2
# -----------------------------------------------------
resource "aws_security_group" "ec2_sg" {
  name        = "${var.resource_prefix}-ec2-sg"
  description = "Security group for EC2 instance running Elastic Agent"

  # SSH access from your IP only
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
    description = "SSH access from current IP"
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
}

# -----------------------------------------------------
# EC2 Instance for Elastic Agent
# -----------------------------------------------------
resource "aws_instance" "elastic_agent" {
  ami                    = var.ec2_ami_id
  instance_type          = var.ec2_instance_type
  key_name               = aws_key_pair.ssh_key.key_name
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]



  tags = {
    Name = "${var.resource_prefix}-elastic-agent"
  }
}