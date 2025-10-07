import json
import logging
import hmac
import hashlib
import datetime
from urllib.parse import quote
import azure.functions as func


def sign(key, msg):
    """Sign a message with a key using HMAC-SHA256"""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    """Generate the signing key for AWS Signature Version 4"""
    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing


def generate_aws_sig_v4(method, url, region, service, access_key, secret_key, 
                        session_token=None, payload='', headers=None):
    """
    Generate AWS Signature Version 4 for API requests
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL including query parameters
        region: AWS region (e.g., 'us-east-1')
        service: AWS service name (e.g., 'bedrock')
        access_key: AWS access key ID
        secret_key: AWS secret access key
        session_token: Optional AWS session token for temporary credentials
        payload: Request body (empty string for GET requests)
        headers: Additional headers to include in signing
    
    Returns:
        dict: Headers to include in the request including Authorization
    """
    
    # Parse URL
    if '://' in url:
        protocol, remainder = url.split('://', 1)
        if '/' in remainder:
            host, path_and_query = remainder.split('/', 1)
            path_and_query = '/' + path_and_query
        else:
            host = remainder
            path_and_query = '/'
    else:
        raise ValueError("Invalid URL format")
    
    # Split path and query
    if '?' in path_and_query:
        canonical_uri, query_string = path_and_query.split('?', 1)
    else:
        canonical_uri = path_and_query
        query_string = ''
    
    # Create timestamp
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')
    
    # Create canonical headers
    canonical_headers_dict = {
        'host': host,
        'x-amz-date': amz_date
    }
    
    if session_token:
        canonical_headers_dict['x-amz-security-token'] = session_token
    
    # Add any additional headers
    if headers:
        for key, value in headers.items():
            canonical_headers_dict[key.lower()] = value
    
    # Sort headers and create canonical string
    sorted_headers = sorted(canonical_headers_dict.items())
    canonical_headers = ''.join([f'{k}:{v}\n' for k, v in sorted_headers])
    signed_headers = ';'.join([k for k, v in sorted_headers])
    
    # Create payload hash
    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    
    # Create canonical request
    canonical_request = f"{method}\n{canonical_uri}\n{query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    
    # Create string to sign
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    
    # Calculate signature
    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    # Create authorization header
    authorization_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    
    # Build response headers
    response_headers = {
        'Authorization': authorization_header,
        'x-amz-date': amz_date,
        'host': host
    }
    
    if session_token:
        response_headers['x-amz-security-token'] = session_token
    
    # Add content-type for POST requests
    if method.upper() in ['POST', 'PUT', 'PATCH']:
        response_headers['content-type'] = 'application/json'
    
    return response_headers


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to generate AWS Signature V4
    
    Expected JSON body:
    {
        "method": "POST",
        "url": "https://bedrock-agent-runtime.us-east-1.amazonaws.com/knowledgebases/KBID/retrieve",
        "region": "us-east-1",
        "service": "bedrock",
        "accessKey": "YOUR_ACCESS_KEY",
        "secretKey": "YOUR_SECRET_KEY",
        "sessionToken": "OPTIONAL_SESSION_TOKEN",
        "payload": "{\"retrievalQuery\":{\"text\":\"your query\"}}",
        "headers": {}
    }
    """
    logging.info('AWS Signature Generator function triggered')
    
    try:
        # Parse request body
        req_body = req.get_json()
        
        # Validate required fields
        required_fields = ['method', 'url', 'region', 'service', 'accessKey', 'secretKey']
        missing_fields = [field for field in required_fields if field not in req_body]
        
        if missing_fields:
            return func.HttpResponse(
                json.dumps({
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }),
                status_code=400,
                mimetype='application/json'
            )
        
        # Extract parameters
        method = req_body['method']
        url = req_body['url']
        region = req_body['region']
        service = req_body['service']
        access_key = req_body['accessKey']
        secret_key = req_body['secretKey']
        session_token = req_body.get('sessionToken')
        payload = req_body.get('payload', '')
        additional_headers = req_body.get('headers', {})
        
        # Generate signature
        signed_headers = generate_aws_sig_v4(
            method=method,
            url=url,
            region=region,
            service=service,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            payload=payload,
            headers=additional_headers
        )
        
        return func.HttpResponse(
            json.dumps({
                'headers': signed_headers,
                'url': url,
                'method': method
            }),
            status_code=200,
            mimetype='application/json'
        )
        
    except ValueError as ve:
        logging.error(f'Validation error: {str(ve)}')
        return func.HttpResponse(
            json.dumps({'error': str(ve)}),
            status_code=400,
            mimetype='application/json'
        )
    except Exception as e:
        logging.error(f'Error generating signature: {str(e)}')
        return func.HttpResponse(
            json.dumps({'error': f'Internal server error: {str(e)}'}),
            status_code=500,
            mimetype='application/json'
        )
