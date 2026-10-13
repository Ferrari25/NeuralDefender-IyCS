# Servicio auth — autenticación y usuarios (dueño de data/auth).
# Se construye desde la raíz del proyecto (ver docker-compose.yml), porque
# necesita también la librería compartida de `libs/`.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/libs:/app/service

WORKDIR /app/service

COPY services/auth/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY libs/ /app/libs/
COPY services/auth/ /app/service/

# Sin privilegios. docker-compose.yml fija el UID/GID real (el del dueño de
# los volúmenes en el host) con `user:`; este es el valor por defecto.
USER 1000:1000

EXPOSE 8000

# UN solo worker a propósito: el control de intentos de login vive en memoria
# (siem_auth.ControlDeIntentos). Con varios workers, cada uno llevaría su propia
# cuenta y el límite de 5 intentos se multiplicaría por la cantidad de workers.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", \
     "--timeout", "900", "--access-logfile", "-", "auth_service:app"]
