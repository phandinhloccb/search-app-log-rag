import os
import logging
import json
import boto3
logger = logging.getLogger()
logger.setLevel(logging.INFO)
queue_url = os.environ["QUEUE_URL"]

def lambda_handler(event, context):
    
    if "challenge" in event:
        return event["challenge"]
    
    if not is_verify_token(event):
        return "OK"    
    if not is_app_mention(event):
        return "OK"    
    
    sgmes = event.get("event").get("text")
    sguser = event.get("event").get("user")
    channel = event.get("event").get("channel")

    sqs = boto3.client('sqs')
    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps({"message": sgmes, "user_id": sguser, "channel": channel}))
        logger.info("Message sent to SQS successfully")
    except Exception as e:
        logger.error(f"Error sending message to SQS: {str(e)}")

    return 'OK'


def is_verify_token(event):

    token = event.get("token")
    if token != os.environ["SLACK_BOT_VERIFY_TOKEN"]:
        return False

    return True
    

def is_app_mention(event):
    return event.get("event").get("type") == "app_mention"
