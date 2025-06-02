import boto3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from botocore.exceptions import ClientError
from datetime import datetime
import base64
import uuid
import re
from decimal import Decimal
import logging
from db_utils import update_thread_email_sending_status, get_thread_email_sending_status

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize the SES client
ses_client = boto3.client('ses', region_name='us-east-2')
dynamodb_resource = boto3.resource('dynamodb')

def update_thread_email_sending_status(conversation_id: str, is_sending: bool) -> bool:
    """Update thread email sending status using direct DynamoDB access."""
    try:
        threads_table = dynamodb_resource.Table('Threads')
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
        threads_table = dynamodb_resource.Table('Threads')
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

def is_domain_verified(domain):
    """
    Check if a domain is verified in SES.
    
    :param domain: The domain to check (e.g., 'example.com')
    :return: Boolean indicating if domain is verified
    """
    try:
        response = ses_client.list_verified_email_addresses()
        verified_domains = [email.split('@')[1] for email in response['VerifiedEmailAddresses']]
        return domain.lower() in verified_domains
    except ClientError as e:
        print(f"Error checking domain verification: {e.response['Error']['Message']}")
        return False

def extract_domain(email):
    """
    Extract domain from email address.
    
    :param email: Email address
    :return: Domain part of email
    """
    match = re.search(r'@(.+)$', email)
    return match.group(1) if match else None

def get_account_email(account_id):
    """
    Retrieves the email associated with the account from DynamoDB.
    
    :param account_id: The unique identifier of the account.
    :return: Tuple of (email, signature) associated with the account.
    """
    table = dynamodb_resource.Table('Users')
    try:
        response = table.get_item(Key={'id': account_id})
        if 'Item' in response:
            return (
                response['Item'].get('responseEmail'),  # Assuming 'responseEmail' holds the email
                response['Item'].get('email_signature', '')  # Get signature, default to empty string
            )
        else:
            print(f"No account found for ID: {account_id}")
            return None, None
    except ClientError as e:
        print(f"Error fetching account email: {e.response['Error']['Message']}")
        return None, None

def log_email_to_dynamodb(account_id, conversation_id, sender, receiver, associated_account, subject, body_text, message_id, in_reply_to=''):
    """
    Logs the sent email details to the Conversations DynamoDB table.
    
    :param conversation_id: The ID of the conversation.
    :param sender: The sender's email address.
    :param receiver: The receiver's email address.
    :param associated_account: The account associated with the email.
    :param body_text: The text content of the email.
    :param message_id: The RFC Message-ID of the email.
    :param in_reply_to: The Message-ID of the email being replied to (empty string for first email).
    """
    table = dynamodb_resource.Table('Conversations')
    current_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        table.put_item(
            Item={
                'conversation_id': conversation_id,
                'is_first_email': '0',  # Mark as not the first email
                'response_id': message_id,
                'in_reply_to': in_reply_to,  # Store the in_reply_to value
                'timestamp': current_timestamp,
                'sender': sender,
                'receiver': receiver,
                'associated_account': account_id,
                'subject': subject,
                'body': body_text,
                's3_location': '',
                'type': "outbound-email",
                'ev_score': ''
            }
        )
        print(f"Successfully logged email to DynamoDB for conversation {conversation_id}")
    except Exception as e:
        print(f"Error writing to DynamoDB: {str(e)}")
        raise e

def get_latest_conversation_by_id(conversation_id):
    """
    Fetch the latest conversation record for a given conversation_id from DynamoDB.
    Returns the item with the latest timestamp.
    """
    table = dynamodb_resource.Table('Conversations')
    try:
        # Query all items with this conversation_id
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('conversation_id').eq(conversation_id)
        )
        items = response.get('Items', [])
        if not items:
            return None
        # Sort by timestamp (descending) and return the latest
        sorted_items = sorted(
            items,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        return sorted_items[0]
    except Exception as e:
        print(f"Error fetching conversation by id: {str(e)}")
        return None

def send_email(sender, recipient, subject, body_text, body_html=None, in_reply_to=None):
    """
    Sends an email using Amazon SES. Adds reply headers if replying to an existing email.

    :param sender: The sender's email address. Must be verified in SES.
    :param recipient: The recipient's email address.
    :param subject: The subject of the email.
    :param body_text: The plain text version of the email body.
    :param body_html: The HTML version of the email body (optional).
    :param in_reply_to: The Message-ID of the email being replied to (optional).
    :return: Tuple of (rfc_message_id, error_message). If successful, error_message will be None.
    """
    # Check if we're in sandbox mode by attempting to get sending statistics
    try:
        ses_client.get_send_statistics()
    except ClientError as e:
        if 'AccessDenied' in str(e):
            print("WARNING: SES account is in sandbox mode. Recipients must be verified.")
            # Check if recipient domain is verified
            recipient_domain = extract_domain(recipient)
            if not is_domain_verified(recipient_domain):
                return None, f"Recipient domain {recipient_domain} is not verified. Please verify the domain in SES or move to production mode."

    msg = MIMEMultipart('alternative')
    # Generate and set a custom Message-ID for threading
    rfc_message_id = f"<{uuid.uuid4()}@homes.automatedconsultancy.com>"
    msg['Message-ID'] = rfc_message_id
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    # Add threading headers if replying to an email
    if in_reply_to:
        msg['In-Reply-To'] = in_reply_to
        msg['References'] = in_reply_to

    # Attach the plain text and HTML parts
    part1 = MIMEText(body_text, 'plain')
    msg.attach(part1)

    if body_html:
        part2 = MIMEText(body_html, 'html')
        msg.attach(part2)

    try:
        # Send the email using send_raw_email (preserving headers exactly)
        response = ses_client.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={
                'Data': msg.as_bytes()
            }
        )
        ses_message_id = response['MessageId']
        print(f"Email sent! SES Message ID: {ses_message_id}")
        return ses_message_id, None
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Failed to send email: {error_message}")
        
        # Provide more helpful error messages for common issues
        if "Email address is not verified" in error_message:
            return None, "Sender email is not verified in SES. Please verify the sender email or use a verified domain."
        elif "not authorized to send from" in error_message:
            return None, "Sender email is not authorized to send from this domain. Please verify the domain in SES."
        elif "sandbox" in error_message.lower():
            return None, "SES account is in sandbox mode. Please request production access or verify the recipient email."
        
        return None, error_message

def lambda_handler(event, context):
    """
    Lambda handler that triggers email sending based on the scheduler input.
    """
    try:
        # Extract required fields from the event
        conversation_id = event.get('conversation_id')
        if not conversation_id:
            return {
                'statusCode': 400,
                'body': 'Missing required field: conversation_id'
            }

        # Check if an email is already being sent for this conversation
        current_status = get_thread_email_sending_status(conversation_id)
        if current_status is None:
            return {
                'statusCode': 500,
                'body': 'Error checking email sending status'
            }
        if current_status:
            return {
                'statusCode': 409,
                'body': 'An email is already being sent for this conversation'
            }

        # Set the sending status to true
        if not update_thread_email_sending_status(conversation_id, True):
            return {
                'statusCode': 500,
                'body': 'Error updating email sending status'
            }

        try:
            # Extract other required fields
            account_id = event.get('account_id')
            recipient = event.get('recipient')
            subject = event.get('subject')
            body_text = event.get('body_text')
            body_html = event.get('body_html')
            in_reply_to = event.get('in_reply_to')

            if not all([account_id, recipient, subject, body_text]):
                raise ValueError("Missing required fields: account_id, recipient, subject, or body_text")

            # Get sender email and signature
            sender_email, signature = get_account_email(account_id)
            if not sender_email:
                raise ValueError(f"Could not find email for account {account_id}")

            # Get the latest conversation to determine if this is a reply
            latest_conversation = get_latest_conversation_by_id(conversation_id)
            if not latest_conversation:
                raise ValueError(f"Could not find conversation {conversation_id}")

            # Send the email
            message_id, error = send_email(
                sender=sender_email,
                recipient=recipient,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                in_reply_to=in_reply_to
            )

            if error:
                raise Exception(f"Failed to send email: {error}")

            # Log the email to DynamoDB
            log_email_to_dynamodb(
                account_id=account_id,
                conversation_id=conversation_id,
                sender=sender_email,
                receiver=recipient,
                associated_account=account_id,
                subject=subject,
                body_text=body_text,
                message_id=message_id,
                in_reply_to=in_reply_to
            )

            return {
                'statusCode': 200,
                'body': {
                    'message': 'Email sent successfully',
                    'message_id': message_id
                }
            }

        finally:
            # Always set the sending status back to false, even if there was an error
            update_thread_email_sending_status(conversation_id, False)

    except Exception as e:
        print(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': str(e)
        }
