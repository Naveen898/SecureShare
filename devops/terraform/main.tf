terraform {
	required_version = ">= 1.3.0"
	required_providers {
		aws = {
			source  = "hashicorp/aws"
			version = ">= 5.0"
		}
	}
}

provider "aws" {
	region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_vpc" "default" { default = true }
data "aws_subnets" "default" { filter { name = "default-for-az" values = ["true"] } }

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "backend" { name = "/secureshare/backend" retention_in_days = 14 }
resource "aws_cloudwatch_log_group" "frontend" { name = "/secureshare/frontend" retention_in_days = 14 }
resource "aws_cloudwatch_log_group" "postgres" { name = "/secureshare/postgres" retention_in_days = 14 }

# ECR repositories
resource "aws_ecr_repository" "backend" { name = "secureshare-backend" image_tag_mutability = "MUTABLE" }
resource "aws_ecr_repository" "frontend" { name = "secureshare-frontend" image_tag_mutability = "MUTABLE" }

# IAM Role for EC2 to access S3, ECR, CloudWatch Logs
resource "aws_iam_role" "ec2_role" {
	name               = "${var.project_name}-ec2-role"
	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
	})
}

resource "aws_iam_policy" "ec2_policy" {
	name   = "${var.project_name}-ec2-policy"
	policy = jsonencode({
		Version = "2012-10-17",
		Statement = [
			{ Effect = "Allow", Action = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], Resource = "*" },
			{ Effect = "Allow", Action = ["ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"], Resource = "*" },
			{ Effect = "Allow", Action = ["s3:GetObject","s3:PutObject","s3:ListBucket","s3:DeleteObject"], Resource = ["arn:aws:s3:::${var.bucket_name}","arn:aws:s3:::${var.bucket_name}/*"] }
		]
	})
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
	role       = aws_iam_role.ec2_role.name
	policy_arn = aws_iam_policy.ec2_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" { name = "${var.project_name}-ec2-profile" role = aws_iam_role.ec2_role.name }

# Security Groups
resource "aws_security_group" "alb_sg" {
	name        = "${var.project_name}-alb-sg"
	description = "ALB SG"
	vpc_id      = data.aws_vpc.default.id
	ingress { from_port = 80 to_port = 80 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
	egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "ec2_sg" {
	name        = "${var.project_name}-ec2-sg"
	description = "EC2 SG"
	vpc_id      = data.aws_vpc.default.id
	ingress { from_port = 80 to_port = 80 protocol = "tcp" security_groups = [aws_security_group.alb_sg.id] }
	egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "rds_sg" {
	name        = "${var.project_name}-rds-sg"
	description = "RDS SG"
	vpc_id      = data.aws_vpc.default.id
	ingress { from_port = 5432 to_port = 5432 protocol = "tcp" security_groups = [aws_security_group.ec2_sg.id] }
	egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

# RDS Postgres (dev-sized)
resource "aws_db_subnet_group" "default" {
	name       = "${var.project_name}-db-subnets"
	subnet_ids = data.aws_subnets.default.ids
}

resource "aws_db_instance" "postgres" {
	identifier              = "${var.project_name}-db"
	engine                  = "postgres"
	engine_version          = "16"
	instance_class          = var.db_instance_class
	username                = var.db_user
	password                = var.db_password
	allocated_storage       = 20
	db_subnet_group_name    = aws_db_subnet_group.default.name
	vpc_security_group_ids  = [aws_security_group.rds_sg.id]
	skip_final_snapshot     = true
	publicly_accessible     = false
}

# ALB
resource "aws_lb" "app" {
	name               = "${var.project_name}-alb"
	load_balancer_type = "application"
	security_groups    = [aws_security_group.alb_sg.id]
	subnets            = data.aws_subnets.default.ids
}

resource "aws_lb_target_group" "app_tg" {
	name        = "${var.project_name}-tg"
	port        = 80
	protocol    = "HTTP"
	vpc_id      = data.aws_vpc.default.id
	target_type = "instance"
	health_check { path = "/" matcher = "200-399" }
}

resource "aws_lb_listener" "http" {
	load_balancer_arn = aws_lb.app.arn
	port              = 80
	protocol          = "HTTP"
	default_action { type = "forward" target_group_arn = aws_lb_target_group.app_tg.arn }
}

# EC2 instance
data "aws_ami" "amazon_linux" {
	most_recent = true
	owners      = ["137112412989"] # Amazon Linux 2/2023
	filter { name = "name" values = ["al2023-ami-*-x86_64"] }
}

resource "aws_instance" "app" {
	ami                         = data.aws_ami.amazon_linux.id
	instance_type               = var.instance_type
	subnet_id                   = data.aws_subnets.default.ids[0]
	vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
	iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
	associate_public_ip_address = true
	key_name                    = var.key_name

	user_data = <<-EOT
#!/bin/bash
set -e
dnf update -y
dnf install -y docker git
systemctl enable docker
systemctl start docker
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
aws ecr get-login-password --region ${data.aws_region.current.name} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com
cat >/opt/docker-compose.yml <<'YML'
version: '3.9'
services:
	backend:
		image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/secureshare-backend:latest
		environment:
			DATABASE_URL: postgresql+asyncpg://${var.db_user}:${var.db_password}@${aws_db_instance.postgres.address}:5432/${var.db_name}
			AWS_REGION: ${data.aws_region.current.name}
			AWS_S3_BUCKET: ${var.bucket_name}
			FRONTEND_BASE_URL: http://localhost
			JWT_SECRET: ${var.jwt_secret}
		expose: ["8000"]
	frontend:
		image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/secureshare-frontend:latest
		ports: ["80:80"]
		depends_on: [backend]
YML
docker-compose -f /opt/docker-compose.yml up -d
EOT

	tags = { Name = "${var.project_name}-ec2" }
}

resource "aws_lb_target_group_attachment" "attach" {
	target_group_arn = aws_lb_target_group.app_tg.arn
	target_id        = aws_instance.app.id
	port             = 80
}