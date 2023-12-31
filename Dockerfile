## ETAPA 1 ##
# Resolviendo depedencias
FROM python:3.11.3-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc

# Instalando dependencias
COPY ./src/requirements.txt ./requirements.txt
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels -r /app/requirements.txt

## ETAPA 2 ##
# Imagen final
FROM python:3.11.3-alpine

# Creando usuario (sin home, password ni shell) para correr aplicación como non-root
RUN addgroup app && adduser app -H -D -s /sbin/nologin -G app

# Creando app directorio
ENV APP_HOME=/app
WORKDIR $APP_HOME

# Cambiando propietario de directorio app a usuario app
RUN chown -R app:app $APP_HOME

# Instalando dependencias
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# Copaindo archivos de la app
COPY ./src/ .
# Copiando script de entrypoint
COPY ./scripts/entrypoint_dev.sh .
RUN chmod +x $APP_HOME/entrypoint_dev.sh

# Exponiendo puerto por defecto
EXPOSE 8000

# Cambiando el usuario a app
USER app

# Ejecutando entrypoint script
ENTRYPOINT ["/app/entrypoint_dev.sh"]
