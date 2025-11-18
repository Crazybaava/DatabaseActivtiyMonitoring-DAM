FROM python:3.12-slim

WORKDIR /DAM

RUN pip install pandas boto3

COPY . .

CMD ["python", "DAMREPORTLAMBDA.py"]