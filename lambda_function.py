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
import json
from db_utils import update_thread_email_sending_status, get_thread_email_sending_status

# Set up logging with detailed format
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize the SES client
ses_client = boto3.client('ses', region_name='us-east-2')
dynamodb_resource = boto3.resource('dynamodb')

def update_thread_email_sending_status(conversation_id: str, is_sending: bool) -> bool:
    """Update thread email sending status using direct DynamoDB access."""
    logger.info(f"Updating email sending status for conversation {conversation_id} to {is_sending}")
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
        logger.error(f"Error updating thread email sending status for conversation {conversation_id}: {str(e)}", exc_info=True)
        return False

def get_thread_email_sending_status(conversation_id: str) -> bool:
    """Get the current email sending status for a thread."""
    logger.info(f"Getting email sending status for conversation {conversation_id}")
    try:
        threads_table = dynamodb_resource.Table('Threads')
        response = threads_table.get_item(
            Key={'conversation_id': conversation_id},
            ProjectionExpression='is_sending_email'
        )
        
        if 'Item' in response:
            status = response['Item'].get('is_sending_email', 'false')
            logger.info(f"Found email sending status for conversation {conversation_id}: {status}")
            return status.lower() == 'true'
        logger.warning(f"No email sending status found for conversation {conversation_id}, defaulting to False")
        return False
    except Exception as e:
        logger.error(f"Error getting thread email sending status for conversation {conversation_id}: {str(e)}", exc_info=True)
        return False

def is_domain_verified(domain):
    """Check if a domain is verified in SES."""
    logger.info(f"Checking if domain {domain} is verified in SES")
    try:
        response = ses_client.list_verified_email_addresses()
        verified_domains = [email.split('@')[1] for email in response['VerifiedEmailAddresses']]
        is_verified = domain.lower() in verified_domains
        logger.info(f"Domain {domain} verification status: {is_verified}")
        return is_verified
    except ClientError as e:
        logger.error(f"Error checking domain verification for {domain}: {e.response['Error']['Message']}", exc_info=True)
        return False

def extract_domain(email):
    """Extract domain from email address."""
    logger.debug(f"Extracting domain from email: {email}")
    match = re.search(r'@(.+)$', email)
    domain = match.group(1) if match else None
    logger.debug(f"Extracted domain: {domain}")
    return domain

def get_account_email(account_id):
    """Retrieves the email associated with the account from DynamoDB."""
    logger.info(f"Getting account email for account ID: {account_id}")
    table = dynamodb_resource.Table('Users')
    try:
        response = table.get_item(Key={'id': account_id})
        if 'Item' in response:
            email = response['Item'].get('responseEmail')
            signature = response['Item'].get('email_signature', '')
            logger.info(f"Found account email: {email}")
            return email, signature
        else:
            logger.warning(f"No account found for ID: {account_id}")
            return None, None
    except ClientError as e:
        logger.error(f"Error fetching account email for {account_id}: {e.response['Error']['Message']}", exc_info=True)
        return None, None

def log_email_to_dynamodb(account_id, conversation_id, sender, receiver, associated_account, subject, body_text, message_id, in_reply_to=''):
    """Logs the sent email details to the Conversations DynamoDB table."""
    logger.info(f"Logging email to DynamoDB for conversation {conversation_id}")
    table = dynamodb_resource.Table('Conversations')
    current_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        item = {
            'conversation_id': conversation_id,
            'is_first_email': '0',
            'response_id': message_id,
            'in_reply_to': in_reply_to,
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
        logger.debug(f"Preparing to write item to DynamoDB: {json.dumps(item, default=str)}")
        
        table.put_item(Item=item)
        logger.info(f"Successfully logged email to DynamoDB for conversation {conversation_id}")
    except Exception as e:
        logger.error(f"Error writing to DynamoDB for conversation {conversation_id}: {str(e)}", exc_info=True)
        raise e

def get_latest_conversation_by_id(conversation_id):
    """Fetch the latest conversation record for a given conversation_id from DynamoDB."""
    logger.info(f"Getting latest conversation for ID: {conversation_id}")
    table = dynamodb_resource.Table('Conversations')
    try:
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('conversation_id').eq(conversation_id)
        )
        items = response.get('Items', [])
        if not items:
            logger.warning(f"No conversations found for ID: {conversation_id}")
            return None
            
        sorted_items = sorted(
            items,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        latest_item = sorted_items[0]
        logger.info(f"Found latest conversation for ID {conversation_id} with timestamp {latest_item.get('timestamp')}")
        return latest_item
    except Exception as e:
        logger.error(f"Error fetching conversation by id {conversation_id}: {str(e)}", exc_info=True)
        return None

def send_email(sender, recipient, subject, body_text, body_html=None, in_reply_to=None):
    """Sends an email using Amazon SES."""
    logger.info(f"Preparing to send email from {sender} to {recipient}")
    logger.debug(f"Email details - Subject: {subject}, In-Reply-To: {in_reply_to}")
    
    try:
        # Check sandbox mode
        try:
            ses_client.get_send_statistics()
        except ClientError as e:
            if 'AccessDenied' in str(e):
                logger.warning("SES account is in sandbox mode. Recipients must be verified.")
                recipient_domain = extract_domain(recipient)
                if not is_domain_verified(recipient_domain):
                    error_msg = f"Recipient domain {recipient_domain} is not verified"
                    logger.error(error_msg)
                    return None, f"{error_msg}. Please verify the domain in SES or move to production mode."

        # Prepare email
        msg = MIMEMultipart('alternative')
        rfc_message_id = f"<{uuid.uuid4()}@homes.automatedconsultancy.com>"
        msg['Message-ID'] = rfc_message_id
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient

        if in_reply_to:
            logger.debug(f"Adding threading headers for reply to {in_reply_to}")
            msg['In-Reply-To'] = in_reply_to
            msg['References'] = in_reply_to

        # Attach email parts
        part1 = MIMEText(body_text, 'plain')
        msg.attach(part1)
        logger.debug("Attached plain text part")

        if body_html:
            part2 = MIMEText(body_html, 'html')
            msg.attach(part2)
            logger.debug("Attached HTML part")

        # Send email
        logger.info("Sending email via SES")
        response = ses_client.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={'Data': msg.as_bytes()}
        )
        
        ses_message_id = response['MessageId']
        logger.info(f"Email sent successfully! SES Message ID: {ses_message_id}")
        return ses_message_id, None
        
    except ClientError as e:
        error_message = e.response['Error']['Message']
        logger.error(f"Failed to send email: {error_message}", exc_info=True)
        
        # Enhanced error messages
        if "Email address is not verified" in error_message:
            error_msg = "Sender email is not verified in SES"
            logger.error(f"{error_msg}: {sender}")
            return None, f"{error_msg}. Please verify the sender email or use a verified domain."
        elif "not authorized to send from" in error_message:
            error_msg = "Sender email is not authorized to send from this domain"
            logger.error(f"{error_msg}: {sender}")
            return None, f"{error_msg}. Please verify the domain in SES."
        elif "sandbox" in error_message.lower():
            error_msg = "SES account is in sandbox mode"
            logger.error(f"{error_msg}. Recipient: {recipient}")
            return None, f"{error_msg}. Please request production access or verify the recipient email."
        
        return None, error_message

def lambda_handler(event, context):
    """Lambda handler that triggers email sending based on the scheduler input."""
    logger.info("Lambda function invoked")
    logger.debug(f"Event received: {json.dumps(event, default=str)}")
    
    try:
        # Extract and validate conversation_id
        conversation_id = event.get('conversation_id')
        if not conversation_id:
            logger.error("Missing required field: conversation_id")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Missing required field: conversation_id',
                    'success': False
                })
            }

        # Check email sending status
        logger.info(f"Checking email sending status for conversation {conversation_id}")
        current_status = get_thread_email_sending_status(conversation_id)
        if current_status is None:
            logger.error(f"Failed to get email sending status for conversation {conversation_id}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': 'Failed to get email sending status',
                    'success': False
                })
            }
            
        if current_status:
            logger.warning(f"Email already being sent for conversation {conversation_id}")
            return {
                'statusCode': 409,
                'body': json.dumps({
                    'error': 'Email already being sent for this conversation',
                    'success': False
                })
            }

        # Update sending status
        logger.info(f"Setting email sending status to True for conversation {conversation_id}")
        if not update_thread_email_sending_status(conversation_id, True):
            logger.error(f"Failed to update email sending status for conversation {conversation_id}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': 'Failed to update email sending status',
                    'success': False
                })
            }

        try:
            # Get conversation details
            logger.info(f"Getting latest conversation for ID: {conversation_id}")
            conversation = get_latest_conversation_by_id(conversation_id)
            if not conversation:
                logger.error(f"No conversation found for ID: {conversation_id}")
                raise ValueError(f"No conversation found for ID: {conversation_id}")

            # Extract email details
            account_id = conversation.get('associated_account')
            if not account_id:
                logger.error(f"No associated account found for conversation {conversation_id}")
                raise ValueError(f"No associated account found for conversation {conversation_id}")

            logger.info(f"Getting account email for account ID: {account_id}")
            sender_email, signature = get_account_email(account_id)
            if not sender_email:
                logger.error(f"No sender email found for account {account_id}")
                raise ValueError(f"No sender email found for account {account_id}")

            # Prepare email content
            recipient = conversation.get('receiver')
            subject = conversation.get('subject', '')
            body_text = conversation.get('body', '')
            in_reply_to = conversation.get('in_reply_to', '')

            if signature:
                logger.debug("Appending email signature")
                body_text += f"\n\n{signature}"

            # Send email
            logger.info(f"Sending email to {recipient}")
            message_id, error = send_email(
                sender_email,
                recipient,
                subject,
                body_text,
                in_reply_to=in_reply_to
            )

            if error:
                logger.error(f"Failed to send email: {error}")
                raise Exception(error)

            # Log the sent email
            logger.info(f"Logging sent email to DynamoDB for conversation {conversation_id}")
            log_email_to_dynamodb(
                account_id,
                conversation_id,
                sender_email,
                recipient,
                account_id,
                subject,
                body_text,
                message_id,
                in_reply_to
            )

            logger.info(f"Successfully completed email sending process for conversation {conversation_id}")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Email sent successfully',
                    'message_id': message_id,
                    'success': True
                })
            }

        except Exception as e:
            logger.error(f"Error in email sending process: {str(e)}", exc_info=True)
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': str(e),
                    'success': False
                })
            }
        finally:
            # Reset sending status
            logger.info(f"Resetting email sending status for conversation {conversation_id}")
            update_thread_email_sending_status(conversation_id, False)

    except Exception as e:
        logger.error(f"Unexpected error in lambda handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Internal server error: {str(e)}',
                'success': False
            })
        }
