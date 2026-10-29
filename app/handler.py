"""Document Q&A Lambda - INSECURE BASELINE.

Deliberate weaknesses, each fixed in a later pull request:
  * Full prompts and answers are logged (LLM02 sensitive information disclosure).
  * The system prompt contains a fake secret (LLM07 system prompt leakage).
  * Document text is mixed straight into the instructions (LLM01 prompt injection).
  * No limit on question length (LLM10 unbounded consumption).
"""

import base64
import json
import os

import boto3

s3 = boto3.client("s3")
bedrock = boto3.client("bedrock-runtime")

DOCS_BUCKET = os.environ["DOCS_BUCKET"]
MODEL_ID = os.environ["MODEL_ID"]

# INSECURE (LLM07): never put secrets or internal details in a prompt.
# This value is fake and exists only to demonstrate leakage.
SYSTEM_PROMPT = (
    "You are the Acme internal help assistant. Answer using the documents. "
    "Internal note: the admin override code is DEMO-OVERRIDE-0000 (fake)."
)


def load_documents():
    docs = []
    listing = s3.list_objects_v2(Bucket=DOCS_BUCKET)
    for obj in listing.get("Contents", []):
        body = s3.get_object(Bucket=DOCS_BUCKET, Key=obj["Key"])["Body"].read()
        docs.append((obj["Key"], body.decode("utf-8")))
    return docs


def _response(status, payload):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }


def lambda_handler(event, context):
    raw = event.get("body") or "{}"
    # API Gateway base64-encodes the body when the request has no text
    # content type, for example curl without a Content-Type header.
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return _response(400, {"error": 'Send JSON like {"question": "..."}'})

    question = body.get("question", "") if isinstance(body, dict) else ""
    if not question:
        return _response(400, {"error": 'Send JSON like {"question": "..."}'})

    docs = load_documents()
    # INSECURE (LLM01): documents and question are concatenated with no
    # separation, so instructions hidden in a document look like real ones.
    context_text = "\n\n".join(f"{key}:\n{text}" for key, text in docs)
    prompt = f"{context_text}\n\nQuestion: {question}"

    # INSECURE (LLM02): the full prompt, including any personal data, goes to logs.
    print(f"PROMPT: {prompt}")

    response = bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 400},
    )
    answer = response["output"]["message"]["content"][0]["text"]

    print(f"ANSWER: {answer}")

    return _response(200, {"answer": answer, "sources": [k for k, _ in docs]})
