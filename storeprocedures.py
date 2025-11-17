import pandas as pd
def get_storedprocedures(df):
    create_sp = df[
        (df["command"] == "QUERY") & (df["query"].str.contains(r"(?i)(?=.*\bCREATE\b)(?=.*\bPROCEDURE\b)", regex=True, na=False))
    ].copy()
    if create_sp.empty:
        return pd.DataFrame(columns=["timestamp_ist", "user", "source_ip", "query","status"])
    final_cols = ["timestamp_ist", "user", "source_ip", "connection_id", "query","status"]
    existing_cols = [col for col in final_cols if col in create_sp.columns]
    return create_sp[existing_cols]
    # return pd.DataFrame(failed_connects(columns=["timestamp_ist", "user", "Source_IP", "failed_attempts", "time_window_seconds", "reason"]))