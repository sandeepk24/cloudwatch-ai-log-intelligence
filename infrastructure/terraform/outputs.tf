output "alb_dns_name" {
  description = "Public ALB DNS name for the API."
  value       = module.ecs.alb_dns_name
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.ecs.cluster_name
}

output "task_role_arn" {
  description = "Task role used for CloudWatch investigation (read-only)."
  value       = module.iam.task_role_arn
}

output "vpc_id" {
  description = "VPC ID."
  value       = module.networking.vpc_id
}
