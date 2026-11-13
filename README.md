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

## 🏗️ Arquitectura del Flujo (El Ecosistema)

El sistema está diseñado bajo una arquitectura de microservicios para IA, donde el orquestador delega el trabajo pesado a agentes especializados.

```text
[ Splunk SIEM / Alertas ]
         │
         ▼ (Lectura de Alertas)
┌─────────────────────────────┐
│ J.A.R.V.I.S. (Orquestador)  ├──────► [ Slack API ] (Notificación)
└──────────────┬──────────────┘
               │
               ▼ (Triaje inicial)
┌─────────────────────────────┐
│ V.I.S.I.O.N. (Analista)     │
└──────┬──────┬───────┬───────┘
       │      │       │
       │      │       └───────► [ Escalado a Humano ] (Desconocido / Complejo)
       │      │
       │      └───────────────► K.A.R.E.N. (Auditoría Código) ──┐
       │                      E.D.I.T.H. (Auditoría Red)    ──┼──► [ Microsoft Defender ] ──► ( Evidencia: /data )
       └──────────────────────► F.R.I.D.A.Y. (Incidente DFIR) ──┘                                      │
                                                                                                    ▼
                                                                                            [ Ollama (Local) ]
                                                                                         (Análisis y EPSS / KEV)


## 🤖 Los Agentes (El Equipo)

1. **J.A.R.V.I.S. (El Orquestador)**  
   Es el director del SOC. Se encarga de leer las alertas entrantes de Splunk, coordinar al agente de triaje (Visión) y llamar al especialista adecuado (F.R.I.D.A.Y., E.D.I.T.H. o K.A.R.E.N.) dependiendo de la naturaleza del incidente.

2. **V.I.S.I.O.N. (Analista de Triaje)**  
   El primer filtro. Lee la alerta cruda y decide, basándose en el contexto, qué agente debe investigar. Si no reconoce la amenaza, la escala a un humano.

3. **F.R.I.D.A.Y. (Especialista DFIR)**  
   Rápida y resolutiva. Es la encargada de los Incidentes (DFIR). Cuando Visión detecta Malware o Ransomware, Friday se conecta a Microsoft Defender, ejecuta playbooks KQL (búsqueda de logins, procesos, conexiones de red), guarda la evidencia y redacta el informe forense.

4. **E.D.I.T.H. (Cazador de Amenazas)**  
   Encuentra lo que otros no ven. Se encarga del Threat Hunting proactivo. Audita la infraestructura en busca de "Equipos Zombie" (máquinas encendidas sin uso humano) o comportamientos anómalos, sin esperar a que salte una alarma.

5. **K.A.R.E.N. (Gestora de Vulnerabilidades y ASPM)**  
   Analiza el entorno y el código. Es la experta en RBVM (Risk-Based Vulnerability Management). Busca CVEs en los endpoints (Defender) y en el código (Trivy/ASPM). Cruza los resultados con las bases de datos de EPSS (probabilidad de explotación) y CISA KEV (explotación activa) para priorizar qué parchear primero. Se actualiza automáticamente cada 24h.

6. **D.E.T.E.C.T.O.R. (Traductor Sigma)**  
   El ingeniero de detección. Convierte reglas universales Sigma (YAML) en consultas KQL nativas para Defender, garantizando la portabilidad del código.

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