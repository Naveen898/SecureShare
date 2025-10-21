variable "project_name" {
  description = "The name of the project"
  type        = string
  default     = "VaultUpload"
}

variable "region" {
  description = "The cloud region for resource deployment"
  type        = string
}

variable "bucket_name" {
  description = "The name of the cloud storage bucket"
  type        = string
}

variable "db_instance_name" {
  description = "The name of the database instance"
  type        = string
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "securesharedb"
}

variable "db_user" {
  description = "The username for the database"
  type        = string
}

variable "db_password" {
  description = "The password for the database"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "key_name" {
  description = "EC2 Key Pair name for SSH"
  type        = string
}

variable "jwt_secret" {
  description = "Secret key for JWT token generation"
  type        = string
  sensitive   = true
}

variable "expiry_duration" {
  description = "Duration for file expiry in hours"
  type        = number
  default     = 24
}