import boto3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from botocore.exceptions import ClientError
import uuid
import re
from datetime import datetime

from config import logger
from utils import LambdaError, invoke_lambda

ses_client = boto3.client('ses', region_name='us-east-2')
dynamodb = boto3.resource('dynamodb')

def get_account_details(account_id, session_id):
    try:
        user_details = invoke_lambda('DBSelect', {
            'body': {
                'table_name': 'Users',
                'index_name': 'id-index',
                'key_name': 'id',
                'key_value': account_id,
                'account_id': account_id,
                'session': session_id,
            }
        })
        if not user_details:
            raise LambdaError(404, "Account not found.")
        
        return user_details[0].get('responseEmail'), user_details[0].get('email_signature', '')
    except Exception as e:
        logger.error(f"Failed to get account details for {account_id}: {e}")
        raise LambdaError(500, "Failed to retrieve account details.")

def send_email_via_ses(sender, recipient, subject, body_text, in_reply_to=None):
    msg = MIMEMultipart('alternative')
    rfc_message_id = f"<{uuid.uuid4()}@homes.automatedconsultancy.com>"
    msg['Message-ID'] = rfc_message_id
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient
    if in_reply_to:
        msg['In-Reply-To'] = in_reply_to
        msg['References'] = in_reply_to

    msg.attach(MIMEText(body_text, 'plain'))
    msg.attach(MIMEText(body_text.replace('\n', '<br>'), 'html'))

    try:
        response = ses_client.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={'Data': msg.as_bytes()}
        )
        return response['MessageId']
    except ClientError as e:
        raise LambdaError(500, f"Failed to send email: {e.response['Error']['Message']}")

def log_email(account_id, conversation_id, sender, receiver, subject, body_text, message_id, in_reply_to, llm_email_type):
    try:
        table = dynamodb.Table('Conversations')
        item = {
            'conversation_id': conversation_id, 'is_first_email': '0', 'response_id': message_id,
            'in_reply_to': in_reply_to, 'timestamp': datetime.utcnow().isoformat(), 'sender': sender,
            'receiver': receiver, 'associated_account': account_id, 'subject': subject, 'body': body_text,
            's3_location': '', 'type': "outbound-email", 'ev_score': ''
        }
        if llm_email_type:
            item['llm_email_type'] = llm_email_type
        table.put_item(Item=item)
    except ClientError as e:
        raise LambdaError(500, f"Failed to log email: {e.response['Error']['Message']}")

def process_and_send_email(event, auth_bp):
    # Extract details from the event
    response_body = event.get('response_body')
    conversation_id = event.get('conversation_id')
    account_id = event.get('account')
    target_email = event.get('target')
    in_reply_to = event.get('in_reply_to', '')
    subject = event.get('subject')
    llm_email_type = event.get('llm_email_type')

    if not all([response_body, conversation_id, account_id, target_email, subject]):
        raise LambdaError(400, "Missing required fields in the event payload.")
        
    # Rate limiting
    invoke_lambda('RateLimitAWS', {'client_id': account_id, 'session': auth_bp})
    if llm_email_type:
        invoke_lambda('RateLimitAI', {'client_id': account_id, 'session': auth_bp})

    sender_email, signature = get_account_details(account_id, auth_bp)
    if not sender_email:
        raise LambdaError(404, "Sender email not found for the account.")

    # Check and update thread 'busy' status
    threads_table = dynamodb.Table('Threads')
    thread_item = threads_table.get_item(Key={'conversation_id': conversation_id}).get('Item')
    if not thread_item or thread_item.get('busy') == False:
        logger.warning(f"Thread {conversation_id} is not busy or does not exist. Skipping email send.")
        return {"message": "Thread not busy, email not sent."}

    threads_table.update_item(
        Key={'conversation_id': conversation_id},
        UpdateExpression='SET busy = :busy',
        ExpressionAttributeValues={':busy': False}
    )

    full_body = f"{response_body}\n\n{signature}" if signature else response_body
    email_subject = subject if subject.lower().startswith('re:') else f"Re: {subject}"

    ses_message_id = send_email_via_ses(sender_email, target_email, email_subject, full_body, in_reply_to)

    log_email(account_id, conversation_id, sender_email, target_email, email_subject, full_body, ses_message_id, in_reply_to, llm_email_type)
    
    return {"message": "Email sent and logged successfully.", "ses_message_id": ses_message_id}
