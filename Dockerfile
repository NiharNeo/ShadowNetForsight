FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SHADOWNET_DATA_DIR=/app/data
WORKDIR /app
COPY requirements.txt requirements.lock.txt ./
RUN pip install --no-cache-dir --upgrade pip==26.2.1 \
    && pip install --no-cache-dir -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu \
    && groupadd --gid 10001 shadownet \
    && useradd --uid 10001 --gid shadownet --no-create-home shadownet
COPY backend backend
COPY frontend frontend
COPY docs/release-evidence/demo-model-studies.json docs/release-evidence/demo-model-studies.json
COPY pipeline pipeline
COPY scripts/manage_users.py scripts/manage_backup.py scripts/demo.py scripts/
COPY datasets/controlled_lab_capture_plan.json datasets/controlled_lab_capture_plan.json
COPY models/cic2018-phase1-lstm models/cic2018-phase1-lstm
COPY models/cic2018-multiday-lstm/evaluation-summary.json models/cic2018-multiday-lstm/evaluation-summary.json
RUN mkdir -p data/uploads data/calibrations && chown -R 10001:10001 data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=3)"
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--limit-concurrency", "32", "--timeout-keep-alive", "5", "--ws-max-size", "8192", "--ws-max-queue", "4"]
