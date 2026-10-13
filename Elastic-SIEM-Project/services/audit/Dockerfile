# Servicio audit — registro append-only encadenado (dueño de data/audit).
# Se construye desde la raíz del proyecto (ver docker-compose.yml), porque
# necesita también la librería compartida de `libs/`.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/libs:/app/service

WORKDIR /app/service

COPY services/audit/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY libs/ /app/libs/
COPY services/audit/ /app/service/

# Sin privilegios. docker-compose.yml fija el UID/GID real (el del dueño de
# los volúmenes en el host) con `user:`; este es el valor por defecto.
USER 1000:1000

EXPOSE 8000

# Con un worker basta; igual, append_jsonl toma un flock por escritura, así que
# la cadena de hashes no se rompe aunque se agreguen workers.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", \
     "--timeout", "900", "--access-logfile", "-", "audit_service:app"]
