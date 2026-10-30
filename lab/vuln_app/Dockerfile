FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir flask==3.1.*
COPY app /srv/app
COPY lab/vuln_app/app.py /srv/lab_app.py
ENV LOG_FILE=/logs/app.log
EXPOSE 5000
CMD ["python", "lab_app.py"]
