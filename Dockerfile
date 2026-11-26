FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8790

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir "fastapi>=0.110.0" "uvicorn>=0.29.0" "pydantic>=2.6.0" "httpx>=0.27.0"

COPY app.py treasury_engine.py solana_proof.py index.html ./
COPY static ./static
COPY assets ./assets

EXPOSE 8790

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8790}"]
