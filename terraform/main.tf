# =============================================================================
# INSECURE BASELINE - deliberately weak, for learning only.
#
# Every "INSECURE" comment marks a weakness that a later pull request fixes.
# Deploy, record the "before" state, then run `terraform destroy` the same
# session: the API below has no authentication and calls a paid model.
# =============================================================================

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name = "${var.name_prefix}-${random_id.suffix.hex}"
}


# -----------------------------------------------------------------------------
# Documents bucket
# INSECURE: no customer-managed KMS key, no versioning (LLM04 poisoning goes
# undetected), no access logging. Public access is still blocked: the baseline
# is weak, not reckless.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "docs" {
  bucket        = "${local.name}-docs"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "docs" {
  bucket                  = aws_s3_bucket.docs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "sample_docs" {
  for_each = fileset("${path.module}/../sample-docs", "*.txt")

  bucket = aws_s3_bucket.docs.id
  key    = each.value
  source = "${path.module}/../sample-docs/${each.value}"
  etag   = filemd5("${path.module}/../sample-docs/${each.value}")
}

# -----------------------------------------------------------------------------
# Lambda execution role
# INSECURE: wildcard actions and resources for Bedrock and S3 (LLM06 excessive
# agency). The function could invoke any model and read or write any bucket.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "least-privilege"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeOneModel"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:${var.region}::foundation-model/${var.model_id}"
      },
      {
        Sid    = "ReadDocsBucket"
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.docs.arn}/*"
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-*"
      }
            ,{
        Sid    = "VPCAccess"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Lambda function
# INSECURE: not in a VPC, so it has unrestricted internet egress (SSRF and
# exfiltration paths). No reserved concurrency (LLM10). Logs full prompts.
# -----------------------------------------------------------------------------
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../app"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_lambda_function" "qa" {
  function_name    = "${local.name}-qa"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      DOCS_BUCKET = aws_s3_bucket.docs.id
      MODEL_ID    = var.model_id
    }
  }
  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.vpce.id]
  }
}
resource "aws_s3_bucket_versioning" "docs" {
  bucket = aws_s3_bucket.docs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "docs" {
  bucket = aws_s3_bucket.docs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

# INSECURE: no retention, no KMS encryption, no data protection policy, so
# personal data in logged prompts is stored in plain text forever (LLM02).

resource "aws_cloudwatch_log_group" "qa" {
  name = "/aws/lambda/${aws_lambda_function.qa.function_name}"
  kms_key_id        = aws_kms_key.main.arn
}

# -----------------------------------------------------------------------------
# HTTP API
# INSECURE: no authorizer and no throttling (LLM02, LLM10). Anyone with the URL
# can call the model at your expense.
# -----------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "http" {
  name          = "${local.name}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "qa" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.qa.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "ask" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "POST /ask"
  target    = "integrations/${aws_apigatewayv2_integration.qa.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_rate_limit  = 2
    throttling_burst_limit = 5
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.qa.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

# ---------- WAF (attached to CloudFront) ----------

resource "aws_wafv2_web_acl" "api" {
  name        = "${var.name_prefix}-api-waf"
  description = "WAF for AI document QA API"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rule 1: Common rules — SQL injection, XSS, bad inputs
  rule {
    name     = "aws-common"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common-rules"
    }
  }

  # Rule 2: Bot Control — automated traffic detection
  rule {
    name     = "aws-bot-control"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesBotControlRuleSet"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-bot-control"
    }
  }

  # Rule 3: Rate limit — block IPs exceeding 100 requests per 5 minutes
  rule {
    name     = "rate-limit"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-limit"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
  }
}

# ---------- CloudFront in front of API Gateway ----------

resource "aws_cloudfront_distribution" "api" {
  enabled         = true
  comment         = "${var.name_prefix} API edge protection"
  web_acl_id      = aws_wafv2_web_acl.api.arn
  is_ipv6_enabled = true

  origin {
    domain_name = "${aws_apigatewayv2_api.http.id}.execute-api.${var.region}.amazonaws.com"
    origin_id   = "apigw"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "apigw"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "Content-Type"]

      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
# ---------- VPC (private network for Lambda) ----------

# The VPC — a private network isolated from the internet
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true    # Required for VPC endpoints
  enable_dns_hostnames = true    # Required for VPC endpoints

  tags = { Name = "${var.name_prefix}-vpc" }
}

# Two private subnets in different AZs for high availability
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.region}a"

  tags = { Name = "${var.name_prefix}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.region}b"

  tags = { Name = "${var.name_prefix}-private-b" }
}

# Route table with NO internet route — keeps subnets truly private
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# Security group for VPC endpoints — allows HTTPS from within the VPC
resource "aws_security_group" "vpce" {
  name_prefix = "${var.name_prefix}-vpce-"
  vpc_id      = aws_vpc.main.id
  description = "Allow Lambda to reach VPC endpoints"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "HTTPS from VPC"
  }

  tags = { Name = "${var.name_prefix}-vpce" }
}

# ---------- VPC Endpoints (private paths to AWS services) ----------

# S3 gateway endpoint — free, uses route tables instead of ENIs
resource "aws_vpc_endpoint" "s3" {
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.${var.region}.s3"
  route_table_ids = [aws_route_table.private.id]

  tags = { Name = "${var.name_prefix}-s3-endpoint" }
}

# Bedrock interface endpoint — creates ENIs in the private subnets
resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true   # SDK calls resolve to private endpoint automatically

  tags = { Name = "${var.name_prefix}-bedrock-endpoint" }
}

# CloudWatch Logs interface endpoint
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-logs-endpoint" }
}


# ---------- KMS (encryption at rest) ----------

resource "aws_kms_key" "main" {
  description             = "${var.name_prefix} encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${var.name_prefix}-key" }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name_prefix}-key"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_kms_key_policy" "main" {
  key_id = aws_kms_key.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      }
    ]
  })
}