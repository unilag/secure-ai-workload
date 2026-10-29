variable "region" {
  description = "AWS region. us-east-1 has the widest Bedrock model availability."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "secure-ai"
}

variable "model_id" {
  description = "Bedrock model ID. Request access to it in the Bedrock console first. Some models need a cross-region inference profile ID instead, e.g. us.amazon.nova-micro-v1:0."
  type        = string
  default     = "amazon.nova-micro-v1:0"
}
