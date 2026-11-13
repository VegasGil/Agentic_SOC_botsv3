# 🛡️ Agentic-SOC: El Centro de Operaciones de Seguridad Autónomo

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![CrewAI](https://img.shields.io/badge/AI-CrewAI-red.svg)](https://www.crewai.com/)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20(Local)-orange.svg)](https://ollama.com/)
[![Splunk](https://img.shields.io/badge/SIEM-Splunk-green.svg)](https://www.splunk.com/)
[![Docker](https://img.shields.io/badge/Docker-Bookworm-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*Agentic-SOC* es la evolución de una arquitectura de ciberseguridad tradicional hacia un **SOC Multi-Agente (SOAR)**. Utiliza Inteligencia Artificial local orquestada mediante agentes autónomos (CrewAI) para investigar alertas de seguridad, buscar amenazas de forma proactiva y priorizar vulnerabilidades basándose en riesgo real.

> 🎥 *(Próximamente)*

---
# 🛡️ Agentic-SOC (BOTS v3 Edition)

Sistema de ciberseguridad defensiva (SOC) Multi-Capa impulsado por Inteligencia Artificial y agentes autónomos. 

## 🚀 Características Principales
- **Arquitectura Multi-Agente:** F.R.I.D.A.Y. (DFIR), E.D.I.T.H. (Threat Hunting), K.A.R.E.N. (RBVM) y V.I.S.I.O.N. (Triaje).
- **RAG (Few-Shot) para Splunk:** Traducción de Lenguaje Natural a SPL (Splunk Processing Language) sin alucinaciones, validado con el dataset real **Splunk BOTS v3** (1.9M de eventos).
- **Threat Intel:** Integración nativa con VirusTotal y PhishDestroy.
- **Observabilidad y Persistencia:** Envío de veredictos en tiempo real vía HEC (HTTP Event Collector) a Splunk.
- **CI/CD:** 21 tests automatizados pasando en GitHub Actions.

## 🛠️ Tecnologías
Python, CrewAI, Ollama (qwen2.5:3b), Splunk Enterprise, Microsoft Defender API, Docker.


---

## 🚀 Despliegue Rápido (Instalación)

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/VegasGil/Agentic-SOC.git
   cd Agentic-SOC


# 2 Instala las dependencias:
python -m venv .venv
source .venv/bin/activate  # En Windows: .\.venv\Scripts\activate
pip install -r requirements.txt

# 3 Configura tus variables de entorno (.env):
# Ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b

# Splunk
SPLUNK_HOST=tu_ip
SPLUNK_REST_PORT=8089
SPLUNK_USER=admin
SPLUNK_PASS=tu_password
HEC_TOKEN=tu_hec_token

# Azure (Defender)
AZURE_TENANT_ID=tu_tenant
AZURE_CLIENT_ID=tu_client
AZURE_CLIENT_SECRET=tu_secret

# Inicia Ollama en segundo plano y Ejecuta el Orquestador
ollama run qwen2.5:3b
python jarvis.py


---

## 🐳 Docker (Recomendado)

El proyecto incluye `Dockerfile` (basado en `python:3.11-slim-bookworm`, que trae SQLite ≥ 3.40 requerido por ChromaDB) y `docker-compose.yml`.

### Modo Demo (sin credenciales reales)

Para probar el flujo completo sin Splunk, Azure ni Ollama reales, usa el archivo `.env.demo`:

```bash
# Linux/Mac
cp .env.demo .env

# Windows (PowerShell)
Copy-Item .env.demo .env

# Construir y ejecutar
docker compose build --no-cache
docker compose up -d

# Verificar que terminó limpio (Exited (0) = éxito)
docker compose ps -a

# Ver logs del flujo completo
docker compose logs --tail=60 agentic-soc

# Salida esperada en modo demo:
🚀 Iniciando Jarvis (Modo Refactorizado con Agentes Autónomos)...
   -> [DEMO MODE] Simulando alertas de Splunk...
🚨 NUEVA ALERTA: demo-alert-001 - Ransomware detected
🤖 [DEMO] Jarvis enruta a: FRIDAY
🕵️ F.R.I.D.A.Y. iniciando DFIR...
   -> [DEMO MODE] F.R.I.D.A.Y. no conecta a Azure real.
✅ Alerta demo-alert-001 marcada como atendida.

# Modo Real (con credenciales)
docker compose build --no-cache
docker compose up -d

🧪 Testing y CI/CD

El proyecto cuenta con un pipeline de GitHub Actions que garantiza que el código no se rompa y que los agentes estén correctamente configurados:

    Pytest: 15 tests unitarios con mocks (no dependen de red ni credenciales).

    Semgrep (SAST): Análisis estático del código Python.

    Trivy (SCA): Escaneo de dependencias vulnerables.

    Docker build: Validación de que la imagen se construye correctamente.
    
### 📥 Descarga de Bases de Datos (Inteligencia)
Este proyecto utiliza bases de datos de MITRE ATT&CK, CAPEC, EPSS y CISA KEV. Por su gran tamaño (más de 50 MB), **no se incluyen en el repositorio**.

Antes de ejecutar el sistema por primera vez, debes descargarlas ejecutando:
```bash
python tools/update_intel.py