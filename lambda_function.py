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

logger = logging.getLogger()

# Initialize the SES client
ses_client = boto3.client('ses', region_name='us-east-2')
dynamodb_resource = boto3.resource('dynamodb')

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

def log_email_to_dynamodb(account_id, conversation_id, sender, receiver, associated_account, subject, body_text, message_id, in_reply_to='', llm_email_type=None):
    """
    Logs the sent email details to the Conversations DynamoDB table.
    
    :param conversation_id: The ID of the conversation.
    :param sender: The sender's email address.
    :param receiver: The receiver's email address.
    :param associated_account: The account associated with the email.
    :param body_text: The text content of the email.
    :param message_id: The RFC Message-ID of the email.
    :param in_reply_to: The Message-ID of the email being replied to (empty string for first email).
    :param llm_email_type: The type of LLM-generated email (if applicable).
    """
    table = dynamodb_resource.Table('Conversations')
    current_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        item = {
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
        
        # Add llm_email_type if provided
        if llm_email_type:
            item['llm_email_type'] = llm_email_type
            
        table.put_item(Item=item)
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
    
    :param event: The event payload from EventBridge Scheduler.
    :param context: The runtime information of the Lambda function.
    """
    print("Received Event:", event)
    
    # Extract details from the event
    response_body = event.get('response_body')
    conversation_id = event.get('conversation_id')
    account_id = event.get('account')
    target_email = event.get('target')
    in_reply_to = event.get('in_reply_to', '')  # Default to empty string if not provided
    subject = event.get('subject')
    llm_email_type = event.get('llm_email_type')  # Get llm_email_type from event

    # If minimal payload, fetch missing info from DynamoDB
    if (not account_id or not target_email or not subject) and conversation_id:
        latest_conv = get_latest_conversation_by_id(conversation_id)
        if latest_conv:
            if not account_id:
                account_id = latest_conv.get('associated_account')
            if not target_email:
                # Use receiver if this is an outbound, sender if inbound
                if latest_conv.get('type') == 'outbound-email':
                    target_email = latest_conv.get('receiver')
                else:
                    target_email = latest_conv.get('sender')
            if not subject:
                subject = latest_conv.get('subject')
            if not in_reply_to:
                in_reply_to = latest_conv.get('response_id', '')
            if not llm_email_type:  # Get llm_email_type from latest conversation if not in event
                llm_email_type = latest_conv.get('llm_email_type')

    if not response_body or not account_id:
        print("Missing response_body or account information.")
        return {
            'statusCode': 400,
            'body': 'Missing response_body or account information.'
        }

    # Retrieve recipient email and signature from DynamoDB
    associated_realtor_email, signature = get_account_email(account_id)
    
    if not associated_realtor_email:
        print("Sender email not found.")
        return {
            'statusCode': 400,
            'body': 'Sender email not found.'
        }
        
    # Get "busy" attribute from the thread
    table = dynamodb_resource.Table('Threads')
    response = table.get_item(Key={'conversation_id': conversation_id})
    print(response)
    if 'Item' in response:
        logger.info(f"Thread {conversation_id} found, busy: {response['Item'].get('busy', True)}")
        busy = response['Item'].get('busy', True) == True
    else:
        logger.warning("Thread not found, defaulting busy to True")
        busy = True
    
    if not busy:
        logger.warning(f"Thread {conversation_id} is not busy, skipping email send")
        return {
            'statusCode': 199,
            'body': 'Thread is busy, skipping email send'
        }
    
    # Update the thread's attribute 'busy' to false
    table.update_item(
        Key={'conversation_id': conversation_id},
        UpdateExpression='SET busy = :busy',
        ExpressionAttributeValues={':busy': False}
    )


    # Append signature to email body if it exists
    if signature:
        response_body = f"{response_body}\n\n{signature}"

    # Email configurations
    body_text = response_body
    body_html = f"""
    <html>
    <head></head>
    <body>
      <p>{response_body.replace('\n', '<br>')}</p>
    </body>
    </html>
    """

    if subject and not subject.lower().startswith('re:'):
        subject = f'Re: {subject}'

    # Send the email
    ses_message_id, error = send_email(
        associated_realtor_email,
        target_email,
        subject,
        response_body,
        body_html,
        in_reply_to
    )

    if error:
        print(f"Failed to send email: {error}")
        return {
            'statusCode': 500,
            'body': f'Failed to send email: {error}'
        }

    # Log the email to DynamoDB
    try:
        log_email_to_dynamodb(
            account_id,
            conversation_id,
            associated_realtor_email,
            target_email,
            account_id,
            subject,
            response_body,
            ses_message_id,
            in_reply_to,
            llm_email_type  # Pass llm_email_type to log_email_to_dynamodb
        )
    except Exception as e:
        print(f"Failed to log email to DynamoDB: {str(e)}")
        return {
            'statusCode': 500,
            'body': f'Failed to log email to DynamoDB: {str(e)}'
        }

    return {
        'statusCode': 200,
        'body': 'Email sent and logged successfully'
    }
