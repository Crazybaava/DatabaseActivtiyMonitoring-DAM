import pandas as pd
def analyze_sessions(df):
    if df.empty:
        return pd.DataFrame(columns=["user", "source_ip", "connection_id", "start_time", "end_time", "duration_sec"])

    sessions = []
    df_valid = df.dropna(subset=['timestamp_ist'])
    
    connects = df_valid[df_valid["command"].str.contains("connect", case=False, na=False)]
    disconnects = df_valid[df_valid["command"].str.contains("disconnect", case=False, na=False)]
    
    for _, conn in connects.iterrows():
        match = disconnects[
            (disconnects["connection_id"] == conn["connection_id"]) &
            (disconnects["timestamp_ist"] > conn["timestamp_ist"])
        ].sort_values(by="timestamp_ist", ascending=True)
        
        end_time = match.iloc[0]["timestamp_ist"] if not match.empty else conn["timestamp_ist"] # Use start if no disconnect
        
        duration = (end_time - conn["timestamp_ist"]).total_seconds()
        
        if duration > 0:
            sessions.append({
                "user": conn["user"],
                "source_ip": conn["source_ip"],
                "connection_id": conn["connection_id"],
                "start_time": conn["timestamp_ist"].strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_sec": round(duration, 2)
            })
            
    return pd.DataFrame(sessions) if sessions else pd.DataFrame(columns=["user", "source_ip", "connection_id", "start_time", "end_time", "duration_sec"])
