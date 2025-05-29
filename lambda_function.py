import boto3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from botocore.exceptions import ClientError
from datetime import datetime
import base64
import uuid



# Initialize the SES client
ses_client = boto3.client('ses', region_name='us-east-2')
dynamodb_resource = boto3.resource('dynamodb')

def get_account_email(account_id):
    """
    Retrieves the email associated with the account from DynamoDB.
    
    :param account_id: The unique identifier of the account.
    :return: The email address associated with the account.
    """
    table = dynamodb_resource.Table('Users')
    try:
        response = table.get_item(Key={'id': account_id})
        if 'Item' in response:
            return response['Item'].get('responseEmail')  # Assuming 'responseEmail' holds the email
        else:
            print(f"No account found for ID: {account_id}")
            return None
    except ClientError as e:
        print(f"Error fetching account email: {e.response['Error']['Message']}")
        return None

def log_email_to_dynamodb(account_id, conversation_id, sender, receiver, associated_account, subject, body_text, message_id):
    """
    Logs the sent email details to the Conversations DynamoDB table.
    
    :param conversation_id: The ID of the conversation.
    :param sender: The sender's email address.
    :param receiver: The receiver's email address.
    :param associated_account: The account associated with the email.
    :param body_text: The text content of the email.
    """
    table = dynamodb_resource.Table('Conversations')
    current_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        table.put_item(
            Item={
                'conversation_id': conversation_id,
                'is_first_email': '0',  # Mark as not the first email
                'response_id': message_id,
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


def send_email(sender, recipient, subject, body_text, body_html=None, in_reply_to=None):
    """
    Sends an email using Amazon SES. Adds reply headers if replying to an existing email.

    :param sender: The sender's email address. Must be verified in SES.
    :param recipient: The recipient's email address.
    :param subject: The subject of the email.
    :param body_text: The plain text version of the email body.
    :param body_html: The HTML version of the email body (optional).
    :param in_reply_to: The Message-ID of the email being replied to (optional).
    :return: Response from SES or an error message.
    """

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
        ses_mid = response['MessageId']
        print(f"Email sent! SES Message ID: <{ses_mid}@us-east-2.amazonses.com>")
        return rfc_message_id  # Return the RFC Message-ID for threading & logging
    except ClientError as e:
        print(f"Failed to send email: {e.response['Error']['Message']}")
        return e.response['Error']['Message']

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
    in_reply_to = event.get('in_reply_to')
    subject = event.get('subject')

    if not response_body or not account_id:
        print("Missing response_body or account information.")
        return {
            'statusCode': 400,
            'body': 'Missing response_body or account information.'
        }

    if not in_reply_to:
        print("Missing in_reply_to information.")
        return {
            'statusCode': 400,
            'body': 'Missing in_reply_to information.'
        }

    # Retrieve recipient email from DynamoDB
    associated_realtor_email = get_account_email(account_id)
    
    if not associated_realtor_email:
        print("Sender email not found.")
        return {
            'statusCode': 404,
            'body': 'Recipient email not found.'
        }

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

    if not subject.lower().startswith('re:'):
        subject = f'Re: {subject}'

    # Send the email
    message_id = send_email(associated_realtor_email, target_email, subject, body_text, body_html, in_reply_to)
    log_email_to_dynamodb(account_id, conversation_id, associated_realtor_email, target_email, account_id, subject, body_text, message_id)

    return {
        'statusCode': 200,
        'body': 'Email sent successfully.'
    }
