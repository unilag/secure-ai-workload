# =============================================================================
# INSECURE BASELINE - deliberately weak, for learning only.
#
# Every "INSECURE" comment marks a weakness that a later pull request fixes.
# Deploy, record the "before" state, then run `terraform destroy` the same
# session: the API below has no authentication and calls a paid model.
# =============================================================================

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

resource "aws_iam_role_policy" "lambda_wide_open" {
  name = "wide-open"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InsecureBedrockWildcard"
        Effect   = "Allow"
        Action   = "bedrock:*"
        Resource = "*"
      },
      {
        Sid      = "InsecureS3Wildcard"
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
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
}

# INSECURE: no retention, no KMS encryption, no data protection policy, so
# personal data in logged prompts is stored in plain text forever (LLM02).
resource "aws_cloudwatch_log_group" "qa" {
  name = "/aws/lambda/${aws_lambda_function.qa.function_name}"
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
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.qa.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}
