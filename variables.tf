variable "aws_region" {
  description = "The AWS region to deploy resources"
  type        = string
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  description = "The AWS profile to use for deployment"
  type        = string
  default     = "elastic-sa"
}

variable "resource_prefix" {
  description = "Prefix for all resources created by this module"
  type        = string
  default     = "elastic-waf"
  validation {
    condition     = length(var.resource_prefix) <= 32
    error_message = "The resource_prefix must be 32 characters or less due to Firehose name length constraints."
  }
}

variable "default_tags" {
  description = "AWS default tags for resources"
  type        = map(string)
  default     = {}
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ec2_ami_id" {
  description = "EC2 AMI ID"
  type        = string
  default     = "ami-0599b6e53ca798bb2"
}

variable "s3_log_expiration_days" {
  description = "Number of days to keep logs in S3"
  type        = number
  default     = 90
}

variable "waf_scope" {
  description = "Scope of WAF WebACL (REGIONAL or CLOUDFRONT)"
  type        = string
  default     = "REGIONAL"
}