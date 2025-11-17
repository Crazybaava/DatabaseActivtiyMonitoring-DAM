import pandas as pd
def failed_login_events(df):
    failed_connects = df[
        (df["command"] == "FAILED_CONNECT")
    ].copy()
    if failed_connects.empty:
        return pd.DataFrame(columns=["timestamp_ist", "user", "source_ip", "command"])
    failed_connects = failed_connects.sort_values(by="timestamp_ist").set_index('timestamp_ist')
    failed_connects = failed_connects.reset_index()
    final_cols = ["timestamp_ist", "user", "source_ip", "connection_id", "command","status"]
    existing_cols = [col for col in final_cols if col in failed_connects.columns]
    return failed_connects[existing_cols]
    # return pd.DataFrame(failed_connects(columns=["timestamp_ist", "user", "Source_IP", "failed_attempts", "time_window_seconds", "reason"]))