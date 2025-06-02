import boto3
import logging
from typing import Optional

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb')

def update_thread_email_sending_status(conversation_id: str, is_sending: bool) -> bool:
    """Update thread email sending status using direct DynamoDB access."""
    try:
        threads_table = dynamodb.Table('Threads')
        threads_table.update_item(
            Key={'conversation_id': conversation_id},
            UpdateExpression='SET #sending = :sending',
            ExpressionAttributeNames={'#sending': 'is_sending_email'},
            ExpressionAttributeValues={':sending': str(is_sending).lower()}
        )
        logger.info(f"Successfully updated email sending status for conversation {conversation_id} to {is_sending}")
        return True
    except Exception as e:
        logger.error(f"Error updating thread email sending status: {str(e)}")
        return False

def get_thread_email_sending_status(conversation_id: str) -> bool:
    """Get the current email sending status for a thread."""
    try:
        threads_table = dynamodb.Table('Threads')
        response = threads_table.get_item(
            Key={'conversation_id': conversation_id},
            ProjectionExpression='is_sending_email'
        )
        
        if 'Item' in response:
            status = response['Item'].get('is_sending_email', 'false')
            return status.lower() == 'true'
        return False  # Default to False if not set
    except Exception as e:
        logger.error(f"Error getting thread email sending status: {str(e)}")
        return False 