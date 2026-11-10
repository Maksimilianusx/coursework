FROM python:3.13.18-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home app
COPY *.py /app/
COPY realm.json /app/realm.json
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live',timeout=3)"
CMD ["gunicorn","--bind","0.0.0.0:8000","--workers","2","--threads","2","--timeout","30","--access-logfile","-","--error-logfile","-","app:app"]
