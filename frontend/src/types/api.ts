export interface Envelope<T> {
  success: boolean;
  data: T | null;
  error: { code: string; message: string } | null;
  meta: { request_id: string; timestamp: string };
}

export interface LivenessResponse {
  status: string;
  version: string;
}

export interface HealthData {
  status: string;
  version: string;
  aws_mode: string;
  aws_region: string | null;
  ai_provider: string;
  bedrock_configured: boolean;
  strands_configured: boolean;
  mock_aws: boolean;
}

export interface ReadyData {
  status: string;
}

export interface ModuleStatus {
  status: string;
  detail: string;
}

export interface CapabilitiesData {
  ingestion: ModuleStatus;
  analytics: ModuleStatus;
  correlation: ModuleStatus;
  reasoning: ModuleStatus;
}

export interface AppSettings {
  app_name: string;
  app_version: string;
  aws_mode: string;
  aws_region: string | null;
  aws_use_mock: boolean;
  ai_provider: string;
  bedrock_enabled: boolean;
  bedrock_model_id: string;
  bedrock_configured: boolean;
  strands_enabled: boolean;
  strands_configured: boolean;
  cors_origins: string[];
}
