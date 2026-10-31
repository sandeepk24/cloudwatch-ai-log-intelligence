# Terraform — ECS Fargate foundation

This stack provisions a VPC, ALB, ECS Fargate service, and a **read-only** CloudWatch investigation IAM role. It is a skeleton: apply it only after you supply a region and container image.

## What is included

- VPC with public and private subnets
- Application Load Balancer health-checking `GET /health`
- ECS Fargate task for the FastAPI API
- Task role limited to CloudWatch Logs Insights and Metrics read APIs
- Optional Bedrock invoke policy, disabled by default

## What is not included yet

- Frontend hosting (CloudFront / S3)
- Remote state backend
- WAF, custom domains, or autoscaling policies
- Customer log-group resource ARNs (wildcards until ingestion is scoped)

## Usage

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# edit aws_region and container_image
terraform init
terraform plan
```

Do not put AWS account IDs, access keys, or production image URIs in git.

The ECS task uses the standard IAM role credential chain. The application must keep `AWS_USE_MOCK=false` only when this role is attached.
