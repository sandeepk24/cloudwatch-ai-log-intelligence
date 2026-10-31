variable "project_name" {
  description = "Name used for resource prefixes. No account identifiers."
  type        = string
  default     = "cw-ai-logs"
}

variable "environment" {
  description = "Deployment environment name (dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region. Provided at apply time; not baked into application code."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR for the application VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "container_image" {
  description = "Backend container image URI. Supply from CI; do not hardcode a registry account."
  type        = string
}

variable "container_port" {
  description = "Container listen port."
  type        = number
  default     = 8000
}

variable "desired_count" {
  description = "Number of Fargate tasks."
  type        = number
  default     = 1
}

variable "task_cpu" {
  description = "Fargate task CPU units."
  type        = string
  default     = "512"
}

variable "task_memory" {
  description = "Fargate task memory (MiB)."
  type        = string
  default     = "1024"
}

variable "enable_bedrock" {
  description = "Attach Bedrock InvokeModel to the task role. Off until reasoning is implemented."
  type        = bool
  default     = false
}
