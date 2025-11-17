import pandas as pd
import re
def detect_suspicious_queries(df):
    if df.empty:
        return pd.DataFrame(columns=["timestamp_ist", "user", "source_ip", "query"])
    suspicious_keywords = ["DROP", "DELETE", "TRUNCATE", "RENAME"]
    general_pattern = re.compile(r'\b(' + '|'.join(suspicious_keywords) + r')\b', re.IGNORECASE)
    exclusion_pattern = re.compile(r'^\s*DROP\s+(?:PROCEDURE|SP|USER|ROLE)\s+', re.IGNORECASE)
    exclusion_pattern2 = re.compile(r'^\s*GRANT\s+', re.IGNORECASE)
    query_commands = ["query", "prepare", "execute"] 
    query_df = df[df["command"].isin(query_commands) | df["command"].str.contains("query", case=False, na=False)]
    def check_suspicious(q):
        if not isinstance(q, str):
            return False     
        if not general_pattern.search(q):
            return False    
        if exclusion_pattern.match(q) or exclusion_pattern2.match(q):
            return False    
        return True
    suspicious_df = query_df[query_df["query"].apply(check_suspicious)]
    return suspicious_df[["timestamp_ist", "user", "source_ip", "query"]]