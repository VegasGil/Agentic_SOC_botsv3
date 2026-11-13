FROM python:3.11-slim-bookworm

WORKDIR /app

# Instalar dependencias de los agentes (CrewAI, OpenAI, etc.)
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 1200 --retries 10 -r requirements.txt

# Instalar dependencias de Sigma (D.E.T.E.C.T.O.R.)
COPY requirements-detections.txt .
RUN pip install --no-cache-dir -r requirements-detections.txt

# Copiar el resto del código
COPY . .

# Comando por defecto
CMD ["python", "-m", "jarvis"]