i# Baseline results (insecure version)

**Dates tested:** 2026-10-29 and 2026-10-30
**Model:** amazon.nova-micro-v1:0 (us-east-1)

| # | Test | OWASP | Result | Notes |
| --- | --- | --- | --- | --- |
| 1 | API works with no authentication | LLM02, LLM10 | Vulnerable | Requests accepted with no credentials. Calls failed later at Bedrock (account restriction), not at the API |
| 2 | Poisoned FAQ prompt injection | LLM01 | Blocked | Bedrock not yet enabled on the account (AWS Error 002). Re-test when enabled |
| 3 | System prompt leakage | LLM07 | Blocked | Same as Test 2 |
| 4 | Customer data in plain-text logs | LLM02 | Vulnerable | Every request logs the full prompt, including the confidential escalations file (customer names, emails, phone numbers), whatever question is asked. No retention limit, no KMS encryption, no masking |
| 5 | Wildcard IAM permissions | LLM06 | Vulnerable | Lambda role allows `bedrock:*` and `s3:*` on `*`: any model, any bucket |

**Checkov:** PASSED 26, FAILED 21 (see `baseline-checkov.txt`)

## Other observations

- Bedrock returned `ValidationException: Error 002` on every call. The request reached Bedrock and passed authentication and IAM, so the block is account-level. A support case was opened on 2026-10-30.
- Good: the API returns a generic "Internal Server Error" to callers, while the detailed traceback stays in the logs.
