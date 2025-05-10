import json
import boto3
import uuid
import os
from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth
from aws_lambda_powertools import Logger

# --- Config ---
region = 'ap-northeast-1'
service = 'es'
credentials = boto3.Session().get_credentials()
auth = AWSV4SignerAuth(credentials, region, service)

host = os.environ["OPENSEARCH_HOST"]
port = 443
INDEX_NAME = 'logs-vector'

# Logging setup
logger = Logger()

opensearch = OpenSearch(
    hosts=[{'host': host, 'port': port}],
    http_auth=auth,
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection
)

bedrock_client = boto3.client('bedrock-runtime', region_name="ap-northeast-1")

# --- Embedding ---
def get_embedding_from_message(message: str):
    input_body = {
        "inputText": message
    }
    input_body_bytes = json.dumps(input_body).encode('utf-8')

    response = bedrock_client.invoke_model(
        accept="*/*",
        modelId="amazon.titan-embed-text-v2:0",
        body=input_body_bytes,
        contentType="application/json",
    )
    embeddings = json.loads(response.get("body").read()).get("embedding")
    return embeddings

# --- Main processing ---
def process_and_index_log(log_data, doc_id=None):
    if not doc_id:
        doc_id = str(uuid.uuid4())
    
    message = log_data.get('message', '')
    vector = get_embedding_from_message(message)
    logger.info(f"vector message: {message}")

    document = {
        "id": log_data.get('id', doc_id),
        "message": message,
        "timestamp": log_data.get('time', log_data.get('timestamp')),
        "level": log_data.get('level', log_data.get('detected_level')),
        "service": log_data.get('service', log_data.get('service_name')),
        "app": log_data.get('app'),
        "namespace": log_data.get('namespace'),
        "pod": log_data.get('pod'),
        "logger": log_data.get('logger'),
        "thread": log_data.get('thread'),
        "pid": log_data.get('pid'),
        "trace_id": log_data.get('trace_id', log_data.get('traceId')),
        "vector": vector,
        "original_data": log_data
    }
    

    os_response = opensearch.index(index=INDEX_NAME, id=doc_id, body=document)
    print(f"[INFO] Indexed log {doc_id}")
    return doc_id

# --- Lambda handler ---
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    results = []

    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']

        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            content = obj['Body'].read()
            data = json.loads(content)

            doc_id = str(uuid.uuid4())
            process_and_index_log(data, doc_id)

            results.append({
                "key": key,
                "doc_id": doc_id,
                "status": "indexed"
            })

        except Exception as e:
            logger.error(f"[ERROR] Failed to process {key}: {str(e)}")
            return {
                "statusCode": 500,
                "body": json.dumps({
                    "error": str(e),
                    "key": key
                })
            }

    return {
        "statusCode": 200,
        "body": json.dumps({
            "results": results
        })
    }
