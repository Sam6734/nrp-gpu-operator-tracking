FROM nvidia/cuda:12.2.0-base-ubuntu22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt
COPY agent.py /app/

CMD ["python3", "/app/agent.py"]
