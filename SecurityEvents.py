import pandas as pd
import re
def detect_security_events(df):
    if df.empty:
        return pd.DataFrame(columns=["timestamp_ist", "user", "source_ip", "Event_Action"])
        
    security_keywords = [
        "GRANT", "REVOKE", 
        "CREATE USER", "DROP USER", "RENAME USER", 
        "SET PASSWORD", "ALTER USER", 
        "CREATE ROLE", "DROP ROLE", "ALTER ROLE", 
        "SHUTDOWN"
    ]
    pattern_string = r"^\s*(" + "|".join(map(re.escape, security_keywords)) + r")\b"
    security_pattern = re.compile(pattern_string, re.IGNORECASE)

    query_commands = ["query", "prepare", "execute"] 
    query_df = df[df["command"].isin(query_commands) | df["command"].str.contains("query", case=False, na=False)].copy()
    
    query_df['query_stripped'] = query_df["query"].str.strip()

    query_df['Event_Action'] = query_df['query_stripped'].apply(
        lambda q: security_pattern.match(q).group(1).upper() if security_pattern.match(q) else None
    )

    security_df = query_df.dropna(subset=['Event_Action']).copy()
    
    return security_df[["timestamp_ist", "user", "source_ip", "Event_Action"]]