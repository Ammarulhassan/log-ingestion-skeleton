FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir requests
COPY lab/attacker/attacker.py /srv/attacker.py
CMD ["python", "attacker.py"]
