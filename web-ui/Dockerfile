FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/
COPY templates /app/templates/
CMD ["python", "/app/app.py"]
