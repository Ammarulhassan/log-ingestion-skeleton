FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY rules ./rules
COPY logs/sample.log logs/attack.log logs/truth.json ./logs/
COPY docs/runbook.pdf ./docs/runbook.pdf
ENV MODE=ingest PORT=8000 INGEST_FILE=/srv/logs/sample.log
# MODE=web -> dashboard (Render/Fly.io). Default MODE=ingest -> tail log and print JSON lines.
CMD ["sh", "-c", "if [ \"$MODE\" = web ]; then exec gunicorn -b 0.0.0.0:${PORT} app.dashboard:app; else touch \"$INGEST_FILE\"; exec python -m app.ingest \"$INGEST_FILE\" --follow --rules rules/rules.json; fi"]
