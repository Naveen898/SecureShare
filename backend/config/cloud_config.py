import os

# AWS-only configuration after migration from GCP
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "your-s3-bucket")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

CLOUD_CONFIG = {
    "provider": "AWS",
    "s3_bucket": AWS_S3_BUCKET,
    "region": AWS_REGION,
}