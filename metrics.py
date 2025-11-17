import pandas as pd
def get_hourly_breakdown(df):
    if df.empty:
        empty_hours = [0] * 24
        return {
            "labels": list(range(24)),
            "total": empty_hours,
            "success": empty_hours,
            "failed": empty_hours
        }

    df_temp = df.set_index('timestamp_ist')
    all_hours_index = pd.Index(range(24)) 

    def calculate_hourly(data_series):
        hourly_counts = data_series.resample('h').size()
        hourly_data = hourly_counts.groupby(hourly_counts.index.hour).sum()
        
        all_hours = pd.Series(0, index=all_hours_index)
        all_hours.update(hourly_data)
        return [int(x) for x in all_hours.tolist()]

    total_events = calculate_hourly(df_temp['connection_id'])

    success_df = df_temp[df_temp["status"] == 0]
    success_events = calculate_hourly(success_df['connection_id'])

    failed_df = df_temp[(df_temp["status"] != 0) & (df_temp["command"] == "QUERY")]
    failed_events = calculate_hourly(failed_df['connection_id'])
    
    return {
        "labels": all_hours_index.tolist(),
        "total": total_events,
        "success": success_events,
        "failed": failed_events
    }