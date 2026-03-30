FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY app/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY app /app
CMD ["python", "-m", "kopf", "run", "--standalone", "/app/main.py"]
