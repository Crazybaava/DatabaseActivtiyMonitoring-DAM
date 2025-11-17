-----

# DAM Repository

This script is written to generate and send DAM report for AWS RDS (MySQL) instacne. It reads the audit logs stored in S3 Bucket, parses it and performs analysis. The metrics and insights are then shared over email in html format.

It is written in python and AWS SES service to send the email with the html report as an attachment.

-----
