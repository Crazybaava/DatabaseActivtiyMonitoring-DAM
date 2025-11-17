import pandas as pd
from datetime import datetime, timedelta, timezone , date
import sys
import os
import re
import json
from io import StringIO
from SES import send_report_via_ses
from parser import parse_log_line
from metrics import get_hourly_breakdown
from S3filelist import fetch_s3_logs
from DMLandDDL import get_dml_ddl_breakdown
from DMLandDDLCategories import categorize_dml_ddl
from QueryMetrics import query_success_error_metrics
from Suspicious import detect_suspicious_queries
from SecurityEvents import detect_security_events
from DestructiveActions import get_flagged_destructive_actions
from SessionAnalysis import analyze_sessions
from login import failed_login_events
from storeprocedures import get_storedprocedures

try:
    IST = 'Asia/Kolkata'
    TZ_IST = timezone(timedelta(hours=5, minutes=30), 'IST')
except:
    IST = 'UTC'
    TZ_IST = timezone.utc

S3_BUCKET_NAME = os.environ['S3_BUCKET_DAM_LOGS']
HOURS_LOOKBACK = 24

Report_Date = date.today()-timedelta(days=1)

SENDER_EMAIL = "no-reply@tesmail.com"
RECIPIENT_EMAILS = ["johndoe@email.com","johndoe@tesmail.com","bond007@mail.com"]
REPORT_SUBJECT = f"Daily DAM Report - {Report_Date}"
AWS_REGION = os.environ['SES_REGION']
REPORT_FILENAME = f"Auropay_DAM_Report_{Report_Date}.html"

def render_table(df, title, css_class="", flagged_actions=None):
    
    COLUMN_DISPLAY_MAP = {
        "timestamp_ist": "Timestamp (IST)",
        "source_ip": "Source IP",
        "user": "User",
        "query": "Query",
        "status": "Error Code", 
        "failed_attempts": "Failed Attempts",
        "reason": "Reason",
        "connection_id": "Connection ID",
        "start_time": "Start Time",
        "end_time": "End Time",
        "Duration (min)": "Duration (min)",
        "Event_Action": "Event Action"
    }
    
    flagged_actions = flagged_actions or set()
    
    is_breakdown_table = 'Event Action' in df.columns and 'Success Count' in df.columns
    
    if df.empty:
        if is_breakdown_table:
            html = f"<h3 style='margin-top: 15px;'>{title}</h3>"
            html += f"<table class='{css_class}'><thead><tr><th>Event Action</th><th>Success Count</th><th>Failed Count</th></tr></thead><tbody>"
            
            if 'DML' in title:
                all_actions = ['Select Query', 'Insert Query', 'Update Query', 'Delete Row Query']
            elif 'DDL' in title:
                all_actions = [
                    'Created Databases/Schemas', 'Altered Databases/Schemas', 'Dropped Databases/Schemas', 
                    'Created Tables', 'Altered Tables', 'Truncated Tables', 'Dropped Tables',
                    'Created Users/Roles', 'Altered Users/Roles/Passwords', 'Dropped Users/Roles'
                ]
            else:
                all_actions = []
                
            for action in all_actions:
                html += f"<tr><td>{action}</td><td>0</td><td>0</td></tr>"
            html += "</tbody></table>"
            return html
        
        return f"<p>No {title} found.</p>"
    
    html = f"<h3 style='margin-top: 15px;'>{title}</h3>"
    html += f"<table class='{css_class}'><thead><tr>"
    
    for col in df.columns:
        if col == "time_window_seconds":
            continue
        display_col_name = COLUMN_DISPLAY_MAP.get(col, col.replace('_', ' ').title())
        html += f"<th>{display_col_name}</th>"
    html += "</tr></thead><tbody>"
    
    for _, row in df.iterrows():
        row_class = ''
        if css_class == 'security':
            row_class = 'security'

        html += f"<tr class='{row_class}'>"
        for col in df.columns:
            if col == "time_window_seconds":
                continue
                
            display_value = "" if pd.isna(row[col]) else row[col]

            if is_breakdown_table and col == "Event Action":
                action_name = str(display_value)
                if action_name in flagged_actions:
                    html += f"<td><a href='#destructive-events' style='color: #005580; text-decoration: underline; font-weight: bold;'>{action_name}</a></td>"
                else:
                    html += f"<td>{action_name}</td>"

            else:
                if isinstance(row[col], (pd.Timestamp, datetime)):
                    html += f"<td>{row[col].strftime('%Y-%m-%d %H:%M:%S')}</td>"
                else:
                    html += f"<td>{display_value}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    return html

def generate_html_report(df, suspicious_df, failedlogin_df,security_df, session_df, hourly_breakdown, dml_df, ddl_df, output_file, flagged_destructive_actions, storedprocedures):
    
    if df.empty:
        timeframe_start = "N/A"
        timeframe_end = "N/A"
    else:
        timeframe_start = df["timestamp_ist"].min().strftime("%Y-%m-%d %H:%M:%S IST")
        timeframe_end = df["timestamp_ist"].max().strftime("%Y-%m-%d %H:%M:%S IST")

    dml_count, ddl_count = categorize_dml_ddl(df) 
    success_count, error_count, failed_queries_df = query_success_error_metrics(df)

    command_counts = df["command"].value_counts().head(10)
    user_counts = df["user"].value_counts().head(10)
    ip_counts = df["source_ip"].value_counts().head(10) 

    hourly_labels = json.dumps(hourly_breakdown["labels"])
    hourly_success_data = json.dumps(hourly_breakdown["success"])
    hourly_failed_data = json.dumps(hourly_breakdown["failed"])
    
    top_sessions_df = session_df.sort_values(by='duration_sec', ascending=False).head(10).copy()
    top_sessions_df['Duration (min)'] = (top_sessions_df['duration_sec'] / 60).round(2)
    top_sessions_df = top_sessions_df[['user', 'source_ip', 'start_time', 'end_time', 'Duration (min)']]
    
    dml_table_html = render_table(dml_df, "DML Activity", flagged_actions=flagged_destructive_actions)
    ddl_table_html = render_table(ddl_df, "DDL Activity", flagged_actions=flagged_destructive_actions)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Database Activity Monitoring Report</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Inter', Arial, sans-serif; margin: 40px; background-color: #f4f7f9; color: #333;}}
            h1 {{ color: #003366; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
            h2 {{ color: #005580; margin-top: 30px; border-left: 5px solid #005580; padding-left: 10px; }}
            h3 {{ color: #005580; margin-top: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 10px; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); background-color: white;}}
            th, td {{ border: 1px solid #eee; padding: 12px; text-align: left; }}
            th {{ background-color: #e0eaf3; font-weight: bold; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            /* Highlighting for security events */
            tr.suspicious {{ background-color: #ffcccc; color: #cc0000; font-weight: bold; }}
            tr.security {{ background-color: #e0f2f1; color: #004d40; }}
            
            .chart-row {{ display: flex; flex-wrap: wrap; gap: 40px; margin-top: 20px; }}
            .chart-container {{ flex: 1 1 45%; min-width: 300px; height: 350px; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);}}
            
            /* DML/DDL Table Layout */
            .table-pair-container {{ 
                display: flex; 
                gap: 30px; 
                margin-top: 20px; 
                flex-wrap: wrap; 
                justify-content: space-between;
            }}
            .table-container-half {{ 
                flex: 1 1 48%; /* Take up nearly half the space, allowing for gap */
                min-width: 350px; /* Ensure tables are readable on small screens */
            }}
            
            @media (max-width: 768px) {{
                .chart-container, .table-container-half {{ flex: 1 1 100%; height: auto; min-width: unset; }}
                body {{ margin: 20px; }}
            }}
        </style>
    </head>
    <body>
        <h1>Database Activity Monitoring Report</h1>
        <p><b>Source:</b> AWS S3 Bucket: <code>{S3_BUCKET_NAME}</code> (Logs modified in the last {HOURS_LOOKBACK} hours)</p>
        <p><b>Timeframe Analyzed:</b> {timeframe_start} &rarr; {timeframe_end}</p>
        <p><b>Total Events Analyzed:</b> {len(df)}</p>

        <h2>Failed Login Attempts</h2>
        {render_table(failedlogin_df, "", css_class = "security")}

        <h2>Security Events</h2>
        {render_table(security_df, "", css_class = "security")}

        <h2>Summary Metrics</h2>
        <p style="font-size: 1.1em;">
            Total DML Events (All): <b>{dml_count}</b> | 
            Total DDL Events (All): <b>{ddl_count}</b> | 
            Successful Queries: <b>{success_count}</b> | 
            Failed Queries: <b>{error_count}</b>
        </p>

        <h2>DML and DDL Activity Breakdown</h2>
        <div class="table-pair-container">
            <div class="table-container-half">
                {dml_table_html}
            </div>
            <div class="table-container-half">
                {ddl_table_html}
            </div>
        </div>

        <h2 id="destructive-events">Destructive Events Detected</h2>
        {render_table(suspicious_df, "", css_class = "security")}

        <h2 id="stored_procedures">Stored Procedure Create/Alter Events</h2>
        {render_table(storedprocedures,"")}

        <h2>Visual Insights</h2>

        <div class="chart-row">
            <div class="chart-container"><canvas id="cmdChart"></canvas></div>
            <div class="chart-container"><canvas id="userChart"></canvas></div>
        </div>
        <div class="chart-row">
            <div class="chart-container"><canvas id="ipChart"></canvas></div>
            <div class="chart-container"><canvas id="hourlyChart"></canvas></div>
        </div>
        
        <script>

        new Chart(document.getElementById('cmdChart'), {{
            type: 'bar', data: {{ labels: {json.dumps(command_counts.index.tolist())}, datasets: [{{ label: 'Top Commands', data: {json.dumps(command_counts.tolist())}, backgroundColor: '#0074D9' }}] }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ title: {{ display: true, text: 'Top 10 Commands' }} }} }}
        }});

        new Chart(document.getElementById('userChart'), {{
            type: 'bar', data: {{ labels: {json.dumps(user_counts.index.tolist())}, datasets: [{{ label: 'Top Users', data: {json.dumps(user_counts.tolist())}, backgroundColor: '#2ECC40' }}] }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ title: {{ display: true, text: 'Top 10 Users by Activity' }} }} }}
        }});

        new Chart(document.getElementById('ipChart'), {{
            type: 'bar', data: {{ labels: {json.dumps(ip_counts.index.tolist())}, datasets: [{{ label: 'Top 10 Source IP Addresses', data: {json.dumps(ip_counts.tolist())}, backgroundColor: '#FF851B' }}] }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ title: {{ display: true, text: 'Top 10 Source IP Addresses' }} }} }}
        }});

        new Chart(document.getElementById('hourlyChart'), {{
            type: 'line', 
            data: {{ 
                labels: {hourly_labels}, 
                datasets: [
                    {{ label: 'Successful Queries', data: {hourly_success_data}, borderColor: '#2ECC40', fill: false, tension: 0.1, borderWidth: 2 }},
                    {{ label: 'Failed Queries', data: {hourly_failed_data}, borderColor: '#FF4136', fill: false, tension: 0.1, borderWidth: 2 }}
                ] 
            }},
            options: {{ 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: {{ 
                    title: {{ display: true, text: 'Activity Trend by Hour (Success vs. Failed)' }} 
                }}, 
                scales: {{ 
                    x: {{ title: {{ display: true, text: 'Hour of Day (IST)' }} }}, 
                    y: {{ beginAtZero: true }} 
                }} 
            }}
        }});
        </script>

        <h2>Failed Queries</h2>
        {render_table(failed_queries_df, "")}

        <h2>Top 10 Longest Sessions</h2>
        {render_table(top_sessions_df, "")}
        
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Report written to: {output_file}")


def main():
    
    all_records = fetch_s3_logs(S3_BUCKET_NAME, HOURS_LOOKBACK)

    if not all_records:
        print("No valid log lines found from S3 bucket within the specified timeframe. Exiting.")
        return

    df = pd.DataFrame(all_records)

    print("--- Starting Timezone and Session Analysis ---")
    
    df.columns = df.columns.str.lower()
    
    df['timestamp_utc'] = pd.to_datetime(
        df['timestamp_utc'], 
        format='%Y%m%d %H:%M:%S', 
        errors='coerce', 
        utc=True 
    )
    df["timestamp_ist"] = df['timestamp_utc'].dt.tz_convert(IST)
    df.dropna(subset=['timestamp_ist'], inplace=True)
    
    if df.empty:
        print("CRITICAL ERROR: All records were dropped because the timestamp format in the logs did not match the expected '%Y%m%d %H:%M:%S'.")
        print("Please check the 'parse_log_line' function or the log file contents and verify the date format.")
        return 

    suspicious_df = detect_suspicious_queries(df)
    
    security_df = detect_security_events(df)
    failedlogin_df = failed_login_events(df)
    
    session_df = analyze_sessions(df)
    hourly_breakdown = get_hourly_breakdown(df) 
    
    dml_df, ddl_df = get_dml_ddl_breakdown(df)
    flagged_destructive_actions = get_flagged_destructive_actions(suspicious_df)

    storedprocedures = get_storedprocedures(df)

    output_file = f"Auropay_DAM_Report_{Report_Date}.html"
    generate_html_report(df, suspicious_df, failedlogin_df,security_df, session_df, hourly_breakdown, dml_df, ddl_df, output_file, flagged_destructive_actions, storedprocedures)

    print("--- Sending Report via SES ---")
    send_report_via_ses(
        sender=SENDER_EMAIL,
        recipients=RECIPIENT_EMAILS,
        subject=REPORT_SUBJECT,
        attachment_filepath=REPORT_FILENAME,
        region_name=AWS_REGION
    )
if __name__ == "__main__":
    main()
