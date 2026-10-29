output "api_url" {
  description = "POST questions to this URL + /ask"
  value       = "${aws_apigatewayv2_api.http.api_endpoint}/ask"
}

output "docs_bucket" {
  value = aws_s3_bucket.docs.id
}

output "log_group" {
  value = aws_cloudwatch_log_group.qa.name
}
