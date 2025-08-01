# AWS KMS Logs Fetcher Usage Guide

## Basic Command

```bash
python aws-logs-generic.py --access-key YOUR_AWS_ACCESS_KEY --secret-key YOUR_AWS_SECRET_KEY --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_ROLE_NAME --bucket YOUR_S3_BUCKET --service kms --account-id YOUR_ACCOUNT_ID
```

## Required Parameters

- `--access-key`: Your AWS access key ID
- `--secret-key`: Your AWS secret access key
- `--role-arn`: The ARN of the IAM role to assume (format: arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_ROLE_NAME)
- `--bucket`: The S3 bucket name where KMS logs are stored
- `--service`: Set to 'kms'
- `--account-id`: Your AWS account ID

## Optional Parameters

- `--prefix`: Specific prefix within the S3 bucket where logs are stored
- `--region`: AWS region for API calls (default: ap-south-1)
- `--output`: Custom output file name (default: aws_logs_output.json)
- `--once`: Run once and exit (default: runs continuously)
- `--interval`: Time in seconds between fetch cycles when running continuously (default: 60)
- `--lookback`: Minutes to look back for logs when no state exists (default: 60)
- `--regions`: Specific regions to process (by default it auto-discovers regions)
- `--log-file`: Path to the script's log file (default: aws_logs.log)
- `--start-time`: Starting time for log collection (ISO format, e.g., 2025-03-07T10:00:00Z)

## Output

- Logs are saved in JSON format
- Each record is extracted from the 'Records' field
- Each log entry includes metadata about its source and processing time
- Output file is appended to, not overwritten
- State is maintained between runs unless --start-time is specified

## Example with Optional Parameters

```bash
python aws-logs-generic.py \
    --access-key YOUR_AWS_ACCESS_KEY \
    --secret-key YOUR_AWS_SECRET_KEY \
    --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_ROLE_NAME \
    --bucket YOUR_S3_BUCKET \
    --service kms \
    --account-id YOUR_ACCOUNT_ID \
    --prefix logs/kms \
    --region us-east-1 \
    --output kms_logs.json \
    --once \
    --lookback 120 \
    --log-file kms_fetch.log
```
