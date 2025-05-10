import json
import re
import boto3
import os
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth
import urllib.request

# Thiết lập logging
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS setup
region = os.environ.get("AWS_REGION", "ap-northeast-1")
session = boto3.Session(region_name=region)
credentials = session.get_credentials()
awsauth = AWSV4SignerAuth(credentials, region)

# OpenSearch config
opensearch_endpoint = os.environ.get("OPENSEARCH_HOST")
opensearch_index = os.environ.get("OPENSEARCH_INDEX", "logs-vector")

# Khởi tạo OpenSearch client
client = OpenSearch(
    hosts=[{"host": opensearch_endpoint, "port": 443}],
    http_auth=awsauth,
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection,
)


# Bedrock client
bedrock = boto3.client('bedrock-runtime', region_name=region)


# Hàm tạo embeddings thay thế BedrockEmbeddings
def get_embedding(text, model_id="amazon.titan-embed-text-v2:0"):
    try:
        response = bedrock.invoke_model(
            accept="*/*",
            modelId=model_id,
            body=json.dumps({"inputText": text})
        )
        response_body = json.loads(response['body'].read())
        return response_body['embedding']
    except Exception as e:
        logger.error(f"Error getting embedding: {str(e)}")
        raise

# Hàm chat thay thế BedrockChat
def generate_response(prompt, model_id="apac.anthropic.claude-3-5-sonnet-20241022-v2:0"):
    try:
        response = bedrock.invoke_model(
            modelId=model_id,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}]
            })
        )
        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        return f"Error generating summary: {str(e)}"

# === Helper functions ===

def extract_date_from_query(query):
    patterns = [
        r"on\s+(\d{1,2}/\d{1,2}/\d{4})",
        r"from\s+(\d{1,2}/\d{1,2}/\d{4})",
        r"(\d{1,2}/\d{1,2}/\d{4})",
        r"(\d{4}-\d{2}-\d{2})"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, query)
        if match:
            try:
                if "/" in match.group(1):
                    dt = datetime.strptime(match.group(1), "%d/%m/%Y")
                    return dt.strftime("%Y-%m-%d")
                else:
                    dt = datetime.strptime(match.group(1), "%Y-%m-%d")
                    return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
    return None

def extract_log_level(query):
    levels = ["ERROR", "WARN", "INFO", "DEBUG"]
    for level in levels:
        if re.search(rf"\b{level}\b", query, re.IGNORECASE):
            return level.upper()
    return None

def extract_error_code(query):
    match = re.search(r'\b([A-Z_]{3,})\b', query)
    if match and "error" in query.lower() and "code" in query.lower():
        return match.group(1)
    return None

def build_text_for_summary(doc):
    parts = []
    
    if doc.get("timestamp"):
        parts.append(f"Timestamp: {doc['timestamp']}")
    
    parts.append(f"Message: {doc.get('message', 'No message')}")
    
    if doc.get("errorCode"):
        parts.append(f"Error code: {doc['errorCode']}")
    
    if doc.get("service"):
        parts.append(f"Service: {doc['service']}")
    
    if doc.get("level"):
        parts.append(f"Level: {doc['level']}")
        
    return "\n".join(parts)

def vector_search_with_filters(query, k=3):
    try:
        # Lấy query embedding
        embedding = get_embedding(query)
        
        # Trích xuất filters
        date_str = extract_date_from_query(query)
        log_level = extract_log_level(query)
        error_code = extract_error_code(query)
        
        # Log extracted filters
        logger.info(f"Extracted filters - Date: {date_str}, Level: {log_level}, Error Code: {error_code}")
        
        # Base query với vector search
        must_clauses = [{
            "knn": {
                "vector": {
                    "vector": embedding,
                    "k": k
                }
            }
        }]

        # Thêm date filter nếu có
        if date_str:
            must_clauses.append({
                "range": {
                    "timestamp": {
                        "gte": f"{date_str}T00:00:00.000Z",
                        "lte": f"{date_str}T23:59:59.999Z"
                    }
                }
            })

        # Thêm log level filter nếu có
        if log_level:
            must_clauses.append({
                "match": {
                    "level": log_level
                }
            })
            
        # Thêm error code filter nếu có
        if error_code:
            must_clauses.append({
                "match": {
                    "errorCode": error_code
                }
            })

        # Tạo truy vấn
        vector_query = {
            "size": k,
            "query": {
                "bool": {
                    "must": must_clauses
                }
            }
        }
        
        # logger.info(f"Vector search query: {json.dumps(vector_query)}")
        
        # Thực hiện tìm kiếm
        results = client.search(index=opensearch_index, body=vector_query)
        hits = results["hits"]["hits"]
        # Thêm metadata vào kết quả
        for hit in hits:
            logger.info(f"hit score: {hit['_score']}")
            hit["_source"]["_score"] = hit["_score"]
        
        # Lọc kết quả theo ngưỡng điểm
        min_score_threshold = 0.8
        filtered_hits = [hit for hit in hits if hit["_score"] >= min_score_threshold]

        # logger.info(f"hits: {hits}")
        # logger.info(f"Found {len(filtered_hits)} results with scores above {min_score_threshold}")

        
        # Trả về top k kết quả
        return filtered_hits[:k]
        
    except Exception as e:
        logger.error(f"Error in vector search: {str(e)}")
        raise

def format_hits(hits):
    formatted = []
    for hit in hits:
        source = hit["_source"]
        timestamp = source.get("timestamp", "N/A")
        message = source.get("message", "No message")
        service = source.get("service", source.get("app", "unknown"))
        level = source.get("level", "unknown")
        score = source.get("_score", 0)
        
        formatted.append(f"[{timestamp}] [{level}] ({service}) {message} [Score: {score:.2f}]")
    
    return "\n".join(formatted)

def get_summary_from_hits(hits, original_query):
    if not hits:
        return "I couldn't find any information matching your query."
        
    documents = [build_text_for_summary(hit["_source"]) for hit in hits]
    content = "\n\n".join(documents)

    try:
        prompt = f"""You are a DevOps assistant analyzing logs. Based on the following log entries, please:
1. Extract information relevant to the user query: "{original_query}"
2. If you find ERROR logs, highlight the potential issues and their likely causes
3. Suggest possible solutions if errors are detected

If the logs don't contain information relevant to the query, clearly state that no relevant information was found.

Log entries:
{content}

Summary:"""

        response = generate_response(prompt)
        logger.info(f"summary response: {response}")
        return response.strip()
    except Exception as e:
        logger.error(f"Error getting summary: {str(e)}")
        return f"Error generating summary: {str(e)}"

# === Process API Gateway request ===
def process_api_request(query):
    try:
        hits = vector_search_with_filters(query)
        if not hits:
            return {
                "summary": "I couldn't find any information matching your query.",
                "logs": []
            }
            
        summary = get_summary_from_hits(hits, query)
        
        # Format logs for API response
        formatted_logs = []
        for hit in hits:
            source = hit["_source"]
            # Remove the vector to reduce payload size
            if "vector" in source:
                del source["vector"]
            # Add hit score
            source["score"] = hit["_score"]
            formatted_logs.append(source)
            
        return {
            "summary": summary,
            "logs": formatted_logs
        }
    except Exception as e:
        logger.error(f"Error processing API request: {str(e)}")
        raise

# === AWS Lambda entry point ===
def lambda_handler(event, context):

    logger.info(json.dumps(event))
    msg = event['Records'][0]['body']
    logger.info(f"msg: {msg}")

    msg_json = json.loads(msg)
    logger.info(f"msg_json: {msg_json}")
    question = msg_json.get("message")
    user_id = msg_json.get("user_id")
    channel = msg_json.get("channel")

    try:
        result = process_api_request(question)
        post_message_to_channel(channel, result, user_id)
        
        # Return the result
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            'body': json.dumps(result)
        }
    
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
    

def post_message_to_channel(channel, message, user_id):
    try:
        url = "https://slack.com/api/chat.postMessage"
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": "Bearer {0}".format(os.environ["SLACK_BOT_USER_ACCESS_TOKEN"])
        }

        # If message is a dictionary (search results), format it properly
        if isinstance(message, dict):
            summary = message.get("summary", "No summary available")
            logs = message.get("logs", [])
            
            # Format the message with proper line breaks
            formatted_message = f"*Summary:*\n{summary}\n\n"
            
            if logs:
                formatted_message += "*Log Entries:*\n"
                for i, log in enumerate(logs, 1):
                    # Extract key information
                    timestamp = log.get("timestamp", "N/A")
                    log_message = log.get("message", "No message")
                    service = log.get("service", log.get("app", "unknown"))
                    level = log.get("level", "unknown")
                    score = log.get("score", 0)
                    
                    formatted_message += f"*{i}. [{timestamp}] [{level}] - {service}*\n"
                    formatted_message += f"Message: {log_message}\n"
                    formatted_message += f"Score: {score:.2f}\n\n"
            
            message = formatted_message
        
        if user_id:
            message = f"<@{user_id}>\n{message}"

        data = {
            "token": os.environ["SLACK_BOT_VERIFY_TOKEN"],
            "channel": channel,
            "text": message,
        }

        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), method="POST", headers=headers)
        response = urllib.request.urlopen(req)
        logger.info(f"Message sent to channel {channel}, response: {response.status}")
    except Exception as e:
        logger.error(f"Error posting message to channel: {str(e)}")

def is_verify_token(event):
    token = event.get("token")
    if token != os.environ["SLACK_BOT_VERIFY_TOKEN"]:
        logger.warning(f"Invalid token: {token}")
        return False

    return True
    
def is_app_mention(event):
    return event.get("event").get("type") == "app_mention"