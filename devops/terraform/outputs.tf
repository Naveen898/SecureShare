// filepath: devops/terraform/outputs.tf
output "jenkins_public_ip" {
  description = "Public IP address of the Jenkins Controller instance."
  value       = aws_instance.jenkins_controller.public_ip
}

output "app_server_public_ip" {
  description = "Public IP address of the SecureShare App Server instance."
  value       = aws_instance.app_server.public_ip
}

output "rds_endpoint" {
  description = "The endpoint of the RDS instance."
  value       = aws_db_instance.main.endpoint
}

output "s3_bucket_name" {
  description = "The name of the S3 bucket for file storage."
  value       = aws_s3_bucket.storage.id
}
