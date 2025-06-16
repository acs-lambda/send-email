import json
import boto3
from botocore.exceptions import ClientError
from config import logger, AWS_REGION

lambda_client = boto3.client("lambda", region_name=AWS_REGION)

class LambdaError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(f"[{status_code}] {message}")

def create_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body),
    }

def invoke_lambda(function_name, payload, invocation_type="RequestResponse"):
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType=invocation_type,
            Payload=json.dumps(payload),
        )
        response_payload = response["Payload"].read().decode("utf-8")
        parsed_payload = json.loads(response_payload)
        
        if "FunctionError" in response:
            raise LambdaError(500, f"Error in {function_name}: {response_payload}")
        
        if isinstance(parsed_payload, dict) and 'statusCode' in parsed_payload and parsed_payload['statusCode'] != 200:
            body = parsed_payload.get('body')
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    pass
            
            error_message = body.get('error', 'Invocation failed') if isinstance(body, dict) else 'Invocation failed'
            raise LambdaError(parsed_payload['statusCode'], error_message)

        return parsed_payload
    except ClientError as e:
        raise LambdaError(500, f"Failed to invoke {function_name}: {e.response['Error']['Message']}")
    except json.JSONDecodeError:
        raise LambdaError(500, "Failed to parse response from invoked Lambda.")
    except LambdaError:
        raise
    except Exception as e:
        raise LambdaError(500, f"An unexpected error occurred invoking {function_name}: {e}")

def authorize(user_id, session_id):
    invoke_lambda('Authorize', {'user_id': user_id, 'session_id': session_id}) 