#!/usr/bin/env python3
import boto3
import json
import os
import logging
import time
import gzip
import io
import argparse
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from typing import Dict, List, Optional, Any
import csv

logger = logging.getLogger('aws_logs_generic')

class AWSLogFetcher:
    def __init__(self, access_key, secret_key, role_arn, region='us-east-1', default_lookback_minutes=60):
        self.access_key = access_key
        self.secret_key = secret_key
        self.role_arn = role_arn
        self.region = region
        self.default_lookback_minutes = default_lookback_minutes
        
        # State management per service and region
        self.service_states = {}
        self.state_file = "aws_logs_fetch_state.json"
        
        # Track processed files in current session
        self.current_session_files = set()
        
        self.script_start_time = datetime.now(timezone.utc)
        
        # Credential management
        self.last_credential_refresh = None
        self.credential_refresh_interval = 3300  # 55 minutes
        
        # Service configurations based on Wazuh documentation
        self.service_configs = {
            'cloudtrail': {
                'type': 'bucket',
                'path_template': '{base_prefix}/AWSLogs/{suffix}/{organization_id}/{account_id}/CloudTrail/{region}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            },
            'vpcflow': {
                'type': 'bucket',
                'path_template': '{base_prefix}/AWSLogs/{suffix}/{account_id}/vpcflowlogs/{region}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': None,  # VPC logs are not JSON
                'compression': 'gzip'
            },
            'config': {
                'type': 'bucket',
                'path_template': '{base_prefix}/AWSLogs/{suffix}/{account_id}/Config/{region}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'configurationItems',
                'compression': 'gzip'
            },
            'kms': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            },
            'macie': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            },
            'trusted-advisor': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            },
            'guardduty': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}/{month}/{day}/{hour}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            },
            'waf': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}/{month}/{day}/{hour}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            },
            'server_access': {
                'type': 'bucket',
                'path_template': '{base_prefix}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': None,  # S3 access logs are not JSON
                'compression': 'gzip'
            },
            'alb': {
                'type': 'bucket',
                'path_template': '{base_prefix}/AWSLogs/{account_id}/elasticloadbalancing/{region}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{4}Z)_',
                'timestamp_format': '%Y%m%dT%H%MZ',
                'json_structure': None,  # ALB logs are not JSON
                'compression': 'gzip'
            },
            'clb': {
                'type': 'bucket',
                'path_template': '{base_prefix}/AWSLogs/{account_id}/elasticloadbalancing/{region}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{4}Z)_',
                'timestamp_format': '%Y%m%dT%H%MZ',
                'json_structure': None,  # CLB logs are not JSON
                'compression': 'gzip'
            },
            'nlb': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}/{month}/{day}',
                'filename_pattern': r'_(\d{8}T\d{4}Z)_',
                'timestamp_format': '%Y%m%dT%H%MZ',
                'json_structure': None,  # NLB logs are not JSON
                'compression': 'gzip'
            },
            'cisco_umbrella': {
                'type': 'bucket',
                'path_template': '{base_prefix}/{year}-{month}-{day}',
                'filename_pattern': r'_(\d{8}T\d{6}Z)_',
                'timestamp_format': '%Y%m%dT%H%M%SZ',
                'json_structure': 'Records',
                'compression': 'gzip'
            }
        }
        
        self._init_aws_clients()
        self._load_state()
        
    def _should_refresh_credentials(self):
        """Check if credentials should be refreshed based on time elapsed."""
        if self.last_credential_refresh is None:
            return True
            
        elapsed = (datetime.now(timezone.utc) - self.last_credential_refresh).total_seconds()
        return elapsed >= self.credential_refresh_interval
        
    def _refresh_credentials_if_needed(self):
        """Refresh AWS credentials if they're close to expiration."""
        if self._should_refresh_credentials():
            logger.info("Refreshing AWS credentials")
            self._init_aws_clients()
            self.last_credential_refresh = datetime.now(timezone.utc)
            
    def _init_aws_clients(self):
        """Initialize AWS clients using temporary credentials from assumed role."""
        try:
            # Create session with credentials
            self.session = boto3.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region
            )
            
            # Create STS client
            sts_client = self.session.client('sts')
            
            # Assume role
            logger.info(f"Assuming role: {self.role_arn}")
            assumed_role = sts_client.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="AWSLogFetcherSession"
            )
            
            credentials = assumed_role['Credentials']
            
            self.assumed_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=self.region
            )
            
            self.s3_client = self.assumed_session.client('s3')
            logger.info("Successfully initialized AWS clients")
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {str(e)}")
            raise
            
    def _load_state(self):
        """Load the previous state including last processed file for each service and region."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.service_states = state.get('service_states', {})
                    logger.info(f"Loaded state with last processed logs for {len(self.service_states)} service-region combinations")
            else:
                logger.info("No state file found. Starting fresh.")
                self.service_states = {}
        except Exception as e:
            logger.error(f"Error loading state: {str(e)}")
            self.service_states = {}
            
    def _save_state(self):
        """Save the current state including last processed file for each service and region."""
        try:
            state = {
                'service_states': self.service_states,
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
            logger.info(f"Saved state with last processed logs for {len(self.service_states)} service-region combinations")
        except Exception as e:
            logger.error(f"Error saving state: {str(e)}")
            
    def _get_service_key(self, service, region):
        """Generate a unique key for service-region combination."""
        return f"{service}_{region}"
            
    def _get_regions_from_s3(self, bucket_name, service_path):
        """Get available regions for a specific service from S3."""
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=service_path,
                Delimiter="/"
            )
            
            regions = []
            if 'CommonPrefixes' in response:
                for prefix in response['CommonPrefixes']:
                    region = prefix['Prefix'].rstrip('/').split('/')[-1]
                    regions.append(region)
                    
            logger.info(f"Found {len(regions)} regions in {service_path}")
            return regions
        except Exception as e:
            logger.error(f"Error getting regions from S3: {str(e)}")
            return []
    
    def _get_date_prefix(self, date=None):
        """Generate date prefix in YYYY/MM/DD format."""
        if date is None:
            date = datetime.now(timezone.utc)
        return f"{date.strftime('%Y/%m/%d')}"
        
    def _is_gzipped(self, content):
        """Check if content is gzipped."""
        return len(content) >= 2 and content[0] == 0x1f and content[1] == 0x8b
        
    def _decompress_gzip(self, content):
        """Decompress gzipped content."""
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content), mode='rb') as f:
                return f.read().decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decompress gzip content: {str(e)}")
            raise
            
    def _get_last_timestamp_for_service_region(self, service, region):
        """Get the last processed timestamp for a service-region combination."""
        service_key = self._get_service_key(service, region)
        
        if service_key in self.service_states:
            service_state = self.service_states[service_key]
            if 'timestamp' in service_state:
                timestamp_str = service_state['timestamp']
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                    logger.info(f"Found last timestamp for {service_key}: {timestamp}")
                    return timestamp
                except Exception as e:
                    logger.warning(f"Could not parse timestamp from state, using default. Error: {str(e)}")
        
        default_time = self.script_start_time - timedelta(minutes=self.default_lookback_minutes)
        logger.info(f"No previous state found for {service_key}. Using fixed lookback time: {default_time}")
        return default_time
    
    def _extract_timestamp_from_filename(self, key, service):
        """Extract timestamp from filename based on service configuration."""
        try:
            filename = key.split('/')[-1]
            import re
            
            config = self.service_configs.get(service, {})
            pattern = config.get('filename_pattern', r'_(\d{8}T\d{6}Z)_')
            timestamp_format = config.get('timestamp_format', '%Y%m%dT%H%M%SZ')
            
            match = re.search(pattern, filename)
            if match:
                timestamp_str = match.group(1)
                file_timestamp = datetime.strptime(timestamp_str, timestamp_format)
                file_timestamp = file_timestamp.replace(tzinfo=timezone.utc)
                return file_timestamp
        except Exception:
            pass
        return None
        
    def _should_process_file(self, key, last_modified, last_timestamp, service, region):
        """Determine if a file should be processed based on timestamp and session state."""
        if key in self.current_session_files:
            logger.debug(f"Skipping already processed log in this session: {key}")
            return False
            
        file_timestamp = self._extract_timestamp_from_filename(key, service)
        if file_timestamp:
            # Skip if older than last processed timestamp
            if file_timestamp <= last_timestamp:
                logger.debug(f"Skipping file with timestamp {file_timestamp} (older than {last_timestamp}): {key}")
                return False
            
            logger.info(f"Processing file with timestamp {file_timestamp}: {key}")
        else:
            # Fall back to last_modified if can't extract timestamp
            if last_modified <= last_timestamp:
                logger.debug(f"Skipping file modified at {last_modified} (older than {last_timestamp}): {key}")
                return False
                
            logger.info(f"Processing file modified at {last_modified}: {key}")
            
        return True
        
    def _update_service_region_state(self, service, region, key, timestamp):
        """Update the state for a service-region combination."""
        service_key = self._get_service_key(service, region)
        
        self.service_states[service_key] = {
            'last_key': key,
            'timestamp': timestamp.isoformat(),
            'processed_at': datetime.now(timezone.utc).isoformat()
        }
        
        self.current_session_files.add(key)
        
    def _process_log_content(self, content, service, key, output_file):
        """Process log content based on service type."""
        config = self.service_configs.get(service, {})
        json_structure = config.get('json_structure')
        
        try:
            # Handle compression
            if key.endswith('.gz') or self._is_gzipped(content):
                content = self._decompress_gzip(content)
            else:
                content = content.decode('utf-8')
            
            # Process based on service type
            if json_structure:
                # JSON-based logs (CloudTrail, Config, etc.)
                try:
                    json_content = json.loads(content)
                    
                    if json_structure in json_content:
                        log_events = json_content[json_structure]
                        
                        with open(output_file, 'a') as f:
                            for event in log_events:
                                # Add metadata to each event
                                event['_metadata'] = {
                                    'service': service,
                                    'source_file': key,
                                    'processed_at': datetime.now(timezone.utc).isoformat()
                                }
                                f.write(json.dumps(event) + '\n')
                                
                        return len(log_events)
                    else:
                        logger.warning(f"No '{json_structure}' field found in {key}")
                        return 0
                except json.JSONDecodeError:
                    logger.warning(f"Content in {key} is not valid JSON, skipping")
                    return 0
            else:
                # Non-JSON logs (VPC, ALB, S3 access, etc.)
                # Write raw content with metadata
                with open(output_file, 'a') as f:
                    log_entry = {
                        '_metadata': {
                            'service': service,
                            'source_file': key,
                            'processed_at': datetime.now(timezone.utc).isoformat()
                        },
                        'raw_content': content
                    }
                    f.write(json.dumps(log_entry) + '\n')
                
                return 1  # Count as one event for non-JSON logs
                
        except Exception as e:
            logger.error(f"Error processing content from {key}: {str(e)}")
            return 0
        
    def fetch_logs(self, bucket_name, service, base_prefix="", output_file="aws_logs_output.json", 
                   account_id="611780053365", organization_id=None, regions=None):
        """Fetch logs for a specific service from S3."""
        self._refresh_credentials_if_needed()
        
        if service not in self.service_configs:
            logger.error(f"Unsupported service: {service}")
            return
            
        config = self.service_configs[service]
        logger.info(f"Starting to fetch {service} logs from bucket: {bucket_name}, base prefix: {base_prefix}")
        
        # Build service path
        path_template = config['path_template']
        service_path = path_template.format(
            base_prefix=base_prefix.rstrip('/'),
            suffix="",
            organization_id=organization_id or "",
            account_id=account_id,
            region="{region}",
            year="{year}",
            month="{month}",
            day="{day}",
            hour="{hour}"
        )
        
        # Remove region placeholder for path discovery
        discovery_path = service_path.replace("{region}", "").replace("{year}", "").replace("{month}", "").replace("{day}", "").replace("{hour}", "")
        
        # Get available regions
        if regions:
            available_regions = regions
        else:
            available_regions = self._get_regions_from_s3(bucket_name, discovery_path)
            
        if not available_regions:
            logger.error(f"No regions found for {service} logs. Check the path.")
            return
            
        # Get today's and yesterday's date prefixes
        today = datetime.now(timezone.utc)
        today_prefix = self._get_date_prefix(today)
        yesterday = today - timedelta(days=1)
        yesterday_prefix = self._get_date_prefix(yesterday)
        
        total_events = 0
        total_files = 0
        
        for region in available_regions:
            logger.info(f"Processing {service} logs for region: {region}")
            
            last_timestamp = self._get_last_timestamp_for_service_region(service, region)
            
            service_key = self._get_service_key(service, region)
            if service_key not in self.service_states:
                self.service_states[service_key] = {}
            
            region_events = 0
            region_files = 0
                
            for date_prefix in [today_prefix, yesterday_prefix]:
                # Build full path for this region and date
                region_path = service_path.format(
                    region=region,
                    year=date_prefix.split('/')[0],
                    month=date_prefix.split('/')[1],
                    day=date_prefix.split('/')[2],
                    hour="00"  # Default hour for services that need it
                )
                
                logger.info(f"Checking path: {region_path} for logs after {last_timestamp}")
                
                try:
                    paginator = self.s3_client.get_paginator('list_objects_v2')
                    page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=region_path)
                    
                    for page in page_iterator:
                        if 'Contents' not in page:
                            logger.info(f"No objects found in: {region_path}")
                            continue
                        
                        objects = sorted(page['Contents'], key=lambda obj: obj['LastModified'])
                        
                        for obj in objects:
                            key = obj['Key']
                            last_modified = obj['LastModified'].replace(tzinfo=timezone.utc)
                            
                            if not self._should_process_file(key, last_modified, last_timestamp, service, region):
                                continue
                            
                            try:
                                response = self.s3_client.get_object(Bucket=bucket_name, Key=key)
                                content = response['Body'].read()
                                
                                event_count = self._process_log_content(content, service, key, output_file)
                                
                                if event_count > 0:
                                    logger.info(f"Extracted {event_count} events from {key}")
                                    region_events += event_count
                                    total_events += event_count
                                
                                file_timestamp = self._extract_timestamp_from_filename(key, service)
                                if file_timestamp is None:
                                    file_timestamp = last_modified
                                    
                                self._update_service_region_state(service, region, key, file_timestamp)
                                region_files += 1
                                total_files += 1
                                    
                            except Exception as e:
                                logger.error(f"Error processing log {key}: {str(e)}")
                                
                except Exception as e:
                    logger.error(f"Error listing objects for region {region} and date {date_prefix}: {str(e)}")
            
            logger.info(f"Processed {region_files} files with {region_events} events for {service} in region {region}")
            
            if region_files > 0:
                self._save_state()
        
        logger.info(f"Completed fetching {service} logs: {total_files} files processed with {total_events} events extracted")
        
    def run_continuous(self, bucket_name, service, base_prefix="", output_file="aws_logs_output.json", 
                      account_id="611780053365", organization_id=None, regions=None, interval_seconds=60):
        """Run the log fetcher continuously."""
        logger.info(f"Starting continuous log fetcher for {service}. Will check for new logs every {interval_seconds} seconds")
        
        try:
            while True:
                start_time = time.time()
                
                # Refresh credentials if needed before each fetch cycle
                self._refresh_credentials_if_needed()
                
                # Fetch logs
                logger.info("Starting log fetch cycle")
                self.fetch_logs(bucket_name, service, base_prefix, output_file, account_id, organization_id, regions)
                
                elapsed = time.time() - start_time
                sleep_time = max(0, interval_seconds - elapsed)
                
                logger.info(f"Fetch cycle completed in {elapsed:.2f} seconds. Sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("Log fetcher stopped by user")
        except Exception as e:
            logger.error(f"Error in continuous log fetcher: {str(e)}")
            raise

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Fetch AWS service logs from S3 bucket')
    parser.add_argument('--access-key', required=True, help='AWS access key')
    parser.add_argument('--secret-key', required=True, help='AWS secret key')
    parser.add_argument('--role-arn', required=True, help='AWS role ARN to assume')
    parser.add_argument('--bucket', required=True, help='S3 bucket name')
    parser.add_argument('--service', required=True, 
                       choices=['cloudtrail', 'vpcflow', 'config', 'kms', 'macie', 'trusted-advisor', 
                               'guardduty', 'waf', 'server_access', 'alb', 'clb', 'nlb', 'cisco_umbrella'],
                       help='AWS service to fetch logs for')
    parser.add_argument('--prefix', default='', help='S3 prefix to service logs')
    parser.add_argument('--output', default='aws_logs_output.json', help='Output file path')
    parser.add_argument('--region', default='ap-south-1', help='AWS region for API calls')
    parser.add_argument('--interval', type=int, default=60, help='Interval between log fetching runs in seconds')
    parser.add_argument('--lookback', type=int, default=60, help='Minutes to look back for logs when no state exists')
    parser.add_argument('--once', action='store_true', help='Run once and exit instead of continuous mode')
    parser.add_argument('--start-time', help='Starting time for log collection (ISO format, e.g. 2025-03-07T10:00:00Z)')
    parser.add_argument('--log-file', default='aws_logs.log', help='Path to the script log file')
    parser.add_argument('--account-id', default='611780053365', help='AWS account ID')
    parser.add_argument('--organization-id', help='AWS organization ID (for CloudTrail)')
    parser.add_argument('--regions', nargs='+', help='Specific regions to process (default: auto-discover)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(args.log_file),
            logging.StreamHandler()
        ]
    )
    
    logger.info("Starting AWS generic log fetcher")
    
    try:
        fetcher = AWSLogFetcher(
            access_key=args.access_key,
            secret_key=args.secret_key,
            role_arn=args.role_arn,
            region=args.region,
            default_lookback_minutes=args.lookback
        )
        
        if args.start_time:
            try:
                start_time = datetime.fromisoformat(args.start_time.replace('Z', '+00:00'))
                logger.info(f"Using provided start time: {start_time}")
                
                fetcher.script_start_time = start_time
                
                if os.path.exists(fetcher.state_file):
                    logger.info("Removing existing state file to use provided start time")
                    os.rename(fetcher.state_file, f"{fetcher.state_file}.bak")
                    fetcher.service_states = {}
            except ValueError as e:
                logger.error(f"Invalid start time format: {e}")
                logger.info("Using default lookback time instead")
        
        if args.once:
            # Run once and exit
            logger.info("Running in single-fetch mode")
            fetcher.fetch_logs(args.bucket, args.service, args.prefix, args.output, 
                             args.account_id, args.organization_id, args.regions)
        else:
            # Run continuously
            fetcher.run_continuous(args.bucket, args.service, args.prefix, args.output, 
                                 args.account_id, args.organization_id, args.regions, args.interval)
        
        logger.info("AWS generic log fetcher completed")
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 