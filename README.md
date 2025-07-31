# AWS Generic Logs Fetcher

A comprehensive Python script for fetching AWS service logs from S3 buckets, supporting all major AWS services mentioned in the [Wazuh documentation](https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/index.html).

## Features

- **Multi-service support**: Supports 12+ AWS services including CloudTrail, VPC Flow Logs, Config, ALB, WAF, and more
- **Automatic credential refresh**: Handles STS token expiration automatically
- **Incremental processing**: Only processes new logs since last run
- **Multi-region support**: Automatically discovers and processes logs from all AWS regions
- **Flexible output**: JSON output with metadata for easy integration
- **State management**: Maintains progress across restarts
- **Continuous mode**: Can run continuously with configurable intervals
- **Error handling**: Comprehensive error handling and logging

## Supported Services

Based on the Wazuh documentation, this script supports the following AWS services:

| Service | Type | Path Structure | JSON Structure |
|---------|------|----------------|----------------|
| CloudTrail | bucket | `{prefix}/AWSLogs/{suffix}/{org_id}/{account_id}/CloudTrail/{region}/{year}/{month}/{day}` | `Records` |
| VPC Flow Logs | bucket | `{prefix}/AWSLogs/{suffix}/{account_id}/vpcflowlogs/{region}/{year}/{month}/{day}` | None (raw logs) |
| AWS Config | bucket | `{prefix}/AWSLogs/{suffix}/{account_id}/Config/{region}/{year}/{month}/{day}` | `configurationItems` |
| KMS | bucket | `{prefix}/{year}/{month}/{day}` | `Records` |
| Macie | bucket | `{prefix}/{year}/{month}/{day}` | `Records` |
| Trusted Advisor | bucket | `{prefix}/{year}/{month}/{day}` | `Records` |
| GuardDuty | bucket | `{prefix}/{year}/{month}/{day}/{hour}` | `Records` |
| WAF | bucket | `{prefix}/{year}/{month}/{day}/{hour}` | `Records` |
| S3 Server Access | bucket | `{prefix}` | None (raw logs) |
| ALB | bucket | `{prefix}/AWSLogs/{account_id}/elasticloadbalancing/{region}/{year}/{month}/{day}` | None (raw logs) |
| CLB | bucket | `{prefix}/AWSLogs/{account_id}/elasticloadbalancing/{region}/{year}/{month}/{day}` | None (raw logs) |
| NLB | bucket | `{prefix}/{year}/{month}/{day}` | None (raw logs) |
| Cisco Umbrella | bucket | `{prefix}/{year}-{month}-{day}` | `Records` |

## Installation

### Prerequisites

```bash
pip install boto3
```

### Required IAM Permissions

The script requires the following IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::BUCKET_NAME",
                "arn:aws:s3:::BUCKET_NAME/*"
            ]
        }
    ]
}
```

## Usage

### Basic Usage

```bash
# Fetch CloudTrail logs
python aws-logs-generic.py \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --bucket your-logs-bucket \
    --service cloudtrail \
    --prefix msmlogs/

# Fetch ALB logs
python aws-logs-generic.py \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --bucket your-alb-logs-bucket \
    --service alb \
    --prefix alb-logs/

# Fetch VPC Flow Logs
python aws-logs-generic.py \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --bucket your-vpc-logs-bucket \
    --service vpcflow \
    --prefix vpc-logs/
```

### Advanced Usage

```bash
# Run continuously with custom interval
python aws-logs-generic.py \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --bucket your-logs-bucket \
    --service cloudtrail \
    --prefix msmlogs/ \
    --interval 300 \
    --output cloudtrail_events.json

# Run once with specific regions
python aws-logs-generic.py \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --bucket your-logs-bucket \
    --service guardduty \
    --prefix security-logs/ \
    --regions us-east-1 us-west-2 \
    --once

# Start from a specific time
python aws-logs-generic.py \
    --access-key YOUR_ACCESS_KEY \
    --secret-key YOUR_SECRET_KEY \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --bucket your-logs-bucket \
    --service config \
    --prefix config-logs/ \
    --start-time 2025-03-07T10:00:00Z \
    --once
```

### Command Line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--access-key` | Yes | AWS access key |
| `--secret-key` | Yes | AWS secret key |
| `--role-arn` | Yes | AWS role ARN to assume |
| `--bucket` | Yes | S3 bucket name |
| `--service` | Yes | AWS service to fetch logs for |
| `--prefix` | No | S3 prefix to service logs (default: "") |
| `--output` | No | Output file path (default: aws_logs_output.json) |
| `--region` | No | AWS region for API calls (default: ap-south-1) |
| `--interval` | No | Interval between runs in seconds (default: 60) |
| `--lookback` | No | Minutes to look back when no state exists (default: 60) |
| `--once` | No | Run once and exit instead of continuous mode |
| `--start-time` | No | Starting time for log collection (ISO format) |
| `--log-file` | No | Path to the script log file (default: aws_logs.log) |
| `--account-id` | No | AWS account ID (default: 611780053365) |
| `--organization-id` | No | AWS organization ID (for CloudTrail) |
| `--regions` | No | Specific regions to process (default: auto-discover) |

### Service-Specific Configuration

#### CloudTrail
```bash
python aws-logs-generic.py \
    --service cloudtrail \
    --prefix msmlogs/ \
    --organization-id o-xxxxxxxxx \
    --account-id 123456789012
```

#### ALB/CLB
```bash
python aws-logs-generic.py \
    --service alb \
    --prefix alb-logs/ \
    --account-id 123456789012
```

#### VPC Flow Logs
```bash
python aws-logs-generic.py \
    --service vpcflow \
    --prefix vpc-logs/ \
    --account-id 123456789012
```

## Output Format

### JSON-based Services (CloudTrail, Config, etc.)

```json
{
    "eventSource": "ec2.amazonaws.com",
    "eventName": "DescribeInstances",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.168.1.1",
    "userAgent": "aws-cli/2.0.0",
    "_metadata": {
        "service": "cloudtrail",
        "source_file": "s3://bucket/AWSLogs/123456789012/CloudTrail/us-east-1/2025/03/07/123456789012_CloudTrail_us-east-1_20250307T120000Z_abcdef.log.gz",
        "processed_at": "2025-03-07T12:30:00+00:00"
    }
}
```

### Non-JSON Services (VPC, ALB, etc.)

```json
{
    "_metadata": {
        "service": "alb",
        "source_file": "s3://bucket/AWSLogs/123456789012/elasticloadbalancing/us-east-1/2025/03/07/123456789012_elasticloadbalancing_us-east-1_alb_20250307T1200Z_192.168.1.1_abcdef.log.gz",
        "processed_at": "2025-03-07T12:30:00+00:00"
    },
    "raw_content": "http 2025-03-07T12:00:00.123456Z app/alb/123456789012 192.168.1.1:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 0 0 \"GET http://example.com:80/ HTTP/1.1\" \"Mozilla/5.0...\" - - arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abcdef123456 - - - - - - - - -"
}
```

## State Management

The script maintains state in `aws_logs_fetch_state.json` to track the last processed file for each service-region combination:

```json
{
    "service_states": {
        "cloudtrail_us-east-1": {
            "last_key": "AWSLogs/123456789012/CloudTrail/us-east-1/2025/03/07/123456789012_CloudTrail_us-east-1_20250307T120000Z_abcdef.log.gz",
            "timestamp": "2025-03-07T12:00:00+00:00",
            "processed_at": "2025-03-07T12:30:00+00:00"
        }
    },
    "last_updated": "2025-03-07T12:30:00+00:00"
}
```

## Logging

The script provides comprehensive logging with the following levels:
- **INFO**: General operation information
- **DEBUG**: Detailed processing information
- **WARNING**: Non-critical issues
- **ERROR**: Critical errors

Logs are written to both console and file (default: `aws_logs.log`).

## Error Handling

The script includes robust error handling for:
- AWS credential expiration
- S3 access issues
- Network connectivity problems
- Malformed log files
- JSON parsing errors

## Performance Considerations

- **Batch processing**: Processes files in batches to optimize memory usage
- **Incremental updates**: Only processes new files since last run
- **Session deduplication**: Prevents processing the same file multiple times in one session
- **Configurable intervals**: Adjustable sleep intervals for continuous mode

## Integration with Wazuh

This script can be used as a data collector for Wazuh by:

1. **Feeding data to Wazuh**: Configure Wazuh to read the JSON output files
2. **Custom decoders**: Create Wazuh decoders for the JSON output format
3. **Alert correlation**: Use Wazuh's rules engine to analyze the log data
4. **Compliance**: Leverage Wazuh's compliance features with the collected data

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the IAM role has proper S3 permissions
2. **No Regions Found**: Check the S3 path structure and prefix configuration
3. **Credential Expiration**: The script automatically refreshes credentials every 55 minutes
4. **Empty Output**: Verify that logs exist in the specified S3 path and time range

### Debug Mode

Enable debug logging by modifying the logging level in the script:

```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## Examples

### CloudTrail Security Monitoring
```bash
python aws-logs-generic.py \
    --service cloudtrail \
    --prefix security-logs/ \
    --interval 300 \
    --output security_events.json
```

### ALB Performance Monitoring
```bash
python aws-logs-generic.py \
    --service alb \
    --prefix alb-logs/ \
    --interval 60 \
    --output alb_performance.json
```

### VPC Network Analysis
```bash
python aws-logs-generic.py \
    --service vpcflow \
    --prefix vpc-logs/ \
    --interval 600 \
    --output network_traffic.json
```

## Contributing

To add support for new AWS services:

1. Add service configuration to `service_configs` in the `AWSLogFetcher` class
2. Define the path template, filename pattern, and JSON structure
3. Test with sample data from the service
4. Update this README with the new service information

## License

This script is provided as-is for educational and operational purposes. 