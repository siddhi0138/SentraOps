FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
# sentence-transformers pulls in torch, and PyPI's default torch wheel bundles
# the full CUDA runtime (~2GB of nvidia_* packages) this container will never
# use since it has no GPU - install the CPU-only build first so the later
# `pip install -r requirements.txt` finds torch already satisfied and never
# reaches for the CUDA one.
RUN pip install --no-cache-dir --timeout 120 --retries 5 torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
