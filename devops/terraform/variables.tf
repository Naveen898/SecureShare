// filepath: devops/terraform/variables.tf
variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for the private subnet."
  type        = string
  default     = "10.0.2.0/24"
}

variable "instance_type" {
  description = "EC2 instance type for the servers."
  type        = string
  default     = "t2.medium"
}

variable "ami_id" {
  description = "AMI ID for Amazon Linux 2023. Find the latest in your region."
  type        = string
  default     = "ami-0f5ee92e2d63afc18" # Example for ap-south-1
}

variable "db_username" {
  description = "Username for the RDS database."
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Password for the RDS database."
  type        = string
  sensitive   = true
}

variable "s3_bucket_name" {
  description = "The name for the S3 file storage bucket."
  type        = string
}

variable "key_name" {
  description = "Name of the EC2 Key Pair to use for SSH access."
  type        = string
}
