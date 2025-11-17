import pandas as pd

def query_success_error_metrics(df):
    
    if df.empty:
        empty_failed_df = pd.DataFrame(columns=["timestamp_ist", "user", "source_ip", "query", "Error Code"])
        return 0, 0, empty_failed_df

    success_count = len(df[(df["command"] == "QUERY") & (df["status"] == 0)]) 
    error_count = len(df[(df["command"] == "QUERY") & (df["status"] != 0)])
    failed_queries = df[(df["command"] == "QUERY") & (df["status"] != 0)].copy()    
    failed_queries = failed_queries[["timestamp_ist", "user", "source_ip", "query", "status"]]
    
    failed_queries.rename(columns={"status": "Error Code"}, inplace=True)
    
    return success_count, error_count, failed_queries