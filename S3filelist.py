from datetime import datetime, timedelta, timezone
import boto3
from parser import parse_log_line

def fetch_s3_logs(bucket_name, hours_lookback):
    all_records = []
    
    try:
        s3 = boto3.client('s3')
    except Exception as e:
        print(f"Error initializing S3 client (boto3): {e}")
        return []
    
    yesterday = datetime.now() - timedelta(days=1)
    
    folder_prefix = (
        f"mysql/"
        f"{yesterday.strftime('%Y')}/" 
        f"{yesterday.strftime('%m')}/" 
        f"{yesterday.strftime('%d')}/" 
    )
    
    print(f"--- Fetching logs from S3 bucket: '{bucket_name}'")
    print(f"--- Using Prefix: '{folder_prefix}'")
    
    paginator = s3.get_paginator('list_objects_v2')
    
    pages = paginator.paginate(
        Bucket=bucket_name,
        Prefix=folder_prefix
    )

    log_files_fetched = 0
    
    for page in pages:
        if 'Contents' not in page:
            continue
            
        for obj in page['Contents']:
            key = obj['Key']
            if key.endswith('.log'):
                
                log_files_fetched += 1





#     now_utc = datetime.now(timezone.utc)
#     time_threshold = now_utc - timedelta(hours=hours_lookback)
    
#     print(f"--- Fetching logs from S3 bucket: '{bucket_name}' (modified after {time_threshold.strftime('%Y-%m-%d %H:%M:%S UTC')}) ---")

#     paginator = s3.get_paginator('list_objects_v2')
#     pages = paginator.paginate(Bucket=bucket_name)

#     log_files_fetched = 0
    
#     for page in pages:
#         if 'Contents' not in page:
#             continue
            
#         for obj in page['Contents']:
#             key = obj['Key']
#             last_modified = obj['LastModified']
            
#             if key.endswith('.log') and last_modified.replace(tzinfo=timezone.utc) > time_threshold:
                
#                 print(f"Fetching: {key} (Last Modified: {last_modified.strftime('%Y-%m-%d %H:%M:%S UTC')})")
#                 log_files_fetched += 1
                
                try:
                    response = s3.get_object(Bucket=bucket_name, Key=key)
                    file_content = response['Body'].read().decode('utf-8')
                    
                    for line in file_content.splitlines():
                        rec = parse_log_line(line)
                        if rec:
                            all_records.append(rec)
                            
                except Exception as e:
                    print(f"Error processing S3 file {key}: {e}")
                    
    print(f"--- Finished S3 fetching. Total logs processed: {log_files_fetched} ---")
    return all_records


