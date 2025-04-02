output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.elastic_agent.id
}

output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.elastic_agent.public_ip
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for WAF logs"
  value       = aws_s3_bucket.waf_logs.id
}

output "sqs_queue_url" {
  description = "URL of the SQS queue"
  value       = aws_sqs_queue.waf_logs_queue.url
}

output "waf_web_acl_id" {
  description = "ID of the WAF WebACL"
  value       = aws_wafv2_web_acl.waf_acl.id
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF WebACL"
  value       = aws_wafv2_web_acl.waf_acl.arn
}

output "ssh_command" {
  description = "SSH command to connect to the EC2 instance"
  value       = "ssh ec2-user@${aws_instance.elastic_agent.public_ip}"
}

output "waf_protected_url" {
  description = "URL of the WAF-protected API endpoint for testing"
  value       = "${aws_api_gateway_stage.demo_stage.invoke_url}/test"
}

output "test_waf_command" {
  description = "Command to test the WAF with the demo script"
  value       = "./test-waf.sh ${aws_api_gateway_stage.demo_stage.invoke_url}/test"
}

output "elastic_agent_aws_s3_input_config" {
  description = "Sample Elastic Agent AWS S3 input configuration"
  value       = <<-EOT
    - type: aws-s3
      queue_url: ${aws_sqs_queue.waf_logs_queue.url}
      expand_event_list_from_field: Records
  EOT
}