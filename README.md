# AWS Signature V4 Generator - Azure Function

This Azure Function generates AWS Signature Version 4 (SigV4) headers for making authenticated requests to AWS services, specifically designed for AWS Bedrock Knowledge Bases.

## Setup

### Prerequisites
- Azure Functions Core Tools
- Python 3.9 or higher
- Azure subscription

### Deployment

1. **Install Azure Functions Core Tools**:
   ```bash
   npm install -g azure-functions-core-tools@4
   ```

2. **Create a Function App in Azure**:
   ```bash
   az functionapp create \
     --resource-group <your-resource-group> \
     --consumption-plan-location <region> \
     --runtime python \
     --runtime-version 3.9 \
     --functions-version 4 \
     --name <your-function-app-name> \
     --storage-account <your-storage-account>
   ```

3. **Deploy the Function**:
   ```bash
   func azure functionapp publish <your-function-app-name>
   ```

## Usage

### Request Format

Send a POST request to your Azure Function endpoint with the following JSON body:

```json
{
  "method": "POST",
  "url": "https://bedrock-agent-runtime.us-east-1.amazonaws.com/knowledgebases/YOUR_KB_ID/retrieve",
  "region": "us-east-1",
  "service": "bedrock",
  "accessKey": "YOUR_AWS_ACCESS_KEY",
  "secretKey": "YOUR_AWS_SECRET_KEY",
  "sessionToken": "OPTIONAL_SESSION_TOKEN",
  "payload": "{\"retrievalQuery\":{\"text\":\"What is machine learning?\"}}",
  "headers": {}
}
```

### Parameters

- **method** (required): HTTP method (GET, POST, PUT, DELETE, etc.)
- **url** (required): Full AWS service URL
- **region** (required): AWS region (e.g., "us-east-1")
- **service** (required): AWS service name (e.g., "bedrock")
- **accessKey** (required): AWS access key ID
- **secretKey** (required): AWS secret access key
- **sessionToken** (optional): AWS session token for temporary credentials
- **payload** (optional): Request body as a string (empty for GET requests)
- **headers** (optional): Additional headers to include in signing

### Response Format

```json
{
  "headers": {
    "Authorization": "AWS4-HMAC-SHA256 Credential=...",
    "x-amz-date": "20250107T120000Z",
    "host": "bedrock-agent-runtime.us-east-1.amazonaws.com",
    "content-type": "application/json"
  },
  "url": "https://bedrock-agent-runtime.us-east-1.amazonaws.com/knowledgebases/YOUR_KB_ID/retrieve",
  "method": "POST"
}
```

## Examples

### Example 1: Retrieve from Bedrock Knowledge Base

**Request**:
```bash
curl -X POST https://<your-function-app>.azurewebsites.net/api/aws-sig-function?code=<function-key> \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "https://bedrock-agent-runtime.us-east-1.amazonaws.com/knowledgebases/KB123456/retrieve",
    "region": "us-east-1",
    "service": "bedrock",
    "accessKey": "AKIAIOSFODNN7EXAMPLE",
    "secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "payload": "{\"retrievalQuery\":{\"text\":\"What is AWS Bedrock?\"},\"retrievalConfiguration\":{\"vectorSearchConfiguration\":{\"numberOfResults\":5}}}"
  }'
```

**Using the response to call AWS**:
```javascript
// Get signed headers from Azure Function
const response = await fetch('https://<your-function>.azurewebsites.net/api/aws-sig-function', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    method: 'POST',
    url: 'https://bedrock-agent-runtime.us-east-1.amazonaws.com/knowledgebases/KB123456/retrieve',
    region: 'us-east-1',
    service: 'bedrock',
    accessKey: 'YOUR_ACCESS_KEY',
    secretKey: 'YOUR_SECRET_KEY',
    payload: JSON.stringify({
      retrievalQuery: {
        text: 'What is AWS Bedrock?'
      },
      retrievalConfiguration: {
        vectorSearchConfiguration: {
          numberOfResults: 5
        }
      }
    })
  })
});

const { headers, url, method } = await response.json();

// Use signed headers to call AWS
const awsResponse = await fetch(url, {
  method: method,
  headers: headers,
  body: JSON.stringify({
    retrievalQuery: {
      text: 'What is AWS Bedrock?'
    },
    retrievalConfiguration: {
      vectorSearchConfiguration: {
        numberOfResults: 5
      }
    }
  })
});

const data = await awsResponse.json();
console.log(data);
```

### Example 2: Query Bedrock Knowledge Base

**Python Example**:
```python
import requests
import json

# Step 1: Get signed headers from Azure Function
azure_function_url = "https://<your-function>.azurewebsites.net/api/aws-sig-function?code=<key>"

payload_data = {
    "retrievalQuery": {
        "text": "How does machine learning work?"
    },
    "retrievalConfiguration": {
        "vectorSearchConfiguration": {
            "numberOfResults": 10
        }
    }
}

request_data = {
    "method": "POST",
    "url": "https://bedrock-agent-runtime.us-east-1.amazonaws.com/knowledgebases/YOUR_KB_ID/retrieve",
    "region": "us-east-1",
    "service": "bedrock",
    "accessKey": "YOUR_ACCESS_KEY",
    "secretKey": "YOUR_SECRET_KEY",
    "payload": json.dumps(payload_data)
}

# Get signed headers
response = requests.post(azure_function_url, json=request_data)
signed_data = response.json()

# Step 2: Use signed headers to call AWS
aws_response = requests.post(
    signed_data['url'],
    headers=signed_data['headers'],
    json=payload_data
)

print(aws_response.json())
```

## Security Considerations

1. **Never expose AWS credentials in client-side code** - This function should be called from your backend only
2. **Use Azure Function Keys** - Enable function-level authorization
3. **Consider using Azure Key Vault** - Store AWS credentials securely
4. **Use temporary credentials** - Consider using AWS STS for temporary credentials with session tokens
5. **Implement rate limiting** - Protect your function from abuse
6. **Enable CORS carefully** - Only allow trusted origins if calling from a web app

## Supported AWS Services

While designed for Bedrock Knowledge Bases, this function can generate signatures for any AWS service by changing the `service` parameter:

- **bedrock** - Amazon Bedrock
- **s3** - Amazon S3
- **dynamodb** - DynamoDB
- **lambda** - AWS Lambda
- **execute-api** - API Gateway
- And more...

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check that your AWS credentials are correct and have the necessary permissions
2. **403 Forbidden**: Verify that your IAM user/role has permissions for the specific Bedrock Knowledge Base
3. **SignatureDoesNotMatch**: Ensure the payload in the signature request matches exactly what you send to AWS

### Required AWS IAM Permissions

For Bedrock Knowledge Bases, your AWS credentials need:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:Retrieve",
        "bedrock:RetrieveAndGenerate"
      ],
      "Resource": "arn:aws:bedrock:*:*:knowledge-base/*"
    }
  ]
}
```

## Local Development

To test locally:

```bash
func start
```

Then send requests to `http://localhost:7071/api/aws-sig-function`

## License

MIT
