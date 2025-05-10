import os
import logging
import json
import boto3
from aws_lambda_powertools import Logger


logger = Logger()

QUEUE_URL = os.environ["QUEUE_URL"]
VERIFY_TOKEN = os.environ["SLACK_BOT_VERIFY_TOKEN"]

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    if "challenge" in event:
        return {
            "statusCode": 200,
            "body": event["challenge"]
        }
    
    if not is_verify_token(event) or not is_app_mention(event):
        return build_response(200, "OK")
    
    try:
        event_data = event.get("event", {})
        message_data = {
            "message": event_data.get("text"),
            "user_id": event_data.get("user"),
            "channel": event_data.get("channel")
        }
        
        send_to_sqs(message_data)
        return build_response(200, "OK")
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        return build_response(500, "Error")

def send_to_sqs(message_data):
    sqs = boto3.client('sqs')
    try:
        response = sqs.send_message(
            QueueUrl=QUEUE_URL, 
            MessageBody=json.dumps(message_data)
        )
        logger.info(f"Message sent to SQS: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error sending to SQS: {str(e)}", exc_info=True)
        raise

def is_verify_token(event):
    token = event.get("token")
    if token != VERIFY_TOKEN:
        logger.warning(f"Invalid token: {token}")
        return False
    return True

def is_app_mention(event):
    event_type = event.get("event", {}).get("type")
    return event_type == "app_mention"

def build_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": body})
    }
