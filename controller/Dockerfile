FROM python@sha256:9e01bf1ae5db7649a236da7be1e94ffbbbdd7a93f867dd0d8d5720d9e1f89fab

WORKDIR /app

# Build deps for torch/transformers native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install torch CPU-only first (separate index), then the rest
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

# Pre-download Prompt Guard model at build time (uses HF token via build secret)
RUN --mount=type=secret,id=hf_token \
    HF_TOKEN=$(cat /run/secrets/hf_token) \
    python -c "from transformers import pipeline; pipeline('text-classification', model='meta-llama/Llama-Prompt-Guard-2-86M')"

COPY app/ ./app/
COPY tests/ ./tests/

RUN mkdir -p /logs /workspace

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
