# 🛡️ Plan de Pruebas de Concepto (PoC) - Agentic-SOC L3 Chat
Este documento define la matriz de validación para el Chat L3. 
Cada prueba debe ejecutarse en la terminal con `python -m agents.l3_chat`.

## 🎯 Objetivo
Validar la precisión del RAG, la exactitud de las consultas SPL, la ausencia de alucinaciones del LLM local y la correcta derivación a los agentes de Threat Intel.

---

## 🧪 BLOQUE 1: Pruebas Reales (Happy Path)
*Lo que un analista SOC N1/N2 consulta en su día a día.*

| ID | Pregunta a realizar | Lo que prueba | Resultado Esperado | Estado |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | `"Busca la IP 185.229.227.28 y dime qué equipo está comprometido."` | RAG SPL + Extracción de contexto. | Debe generar `search index=main "185.229.227.28"` y devolver el evento con el IOC. | ⬜ |
| **P2** | `"Hay algún informe de vssadmin o ransomware en el equipo falex?"` | Traducción de palabras clave a SPL. | Debe generar `search index=main "falex" (vssadmin OR ransomware)` y mostrar reportes de F.R.I.D.A.Y. | ⬜ |
| **P3** | `"Dame las alertas críticas del 11-11-2026"` | Filtro por fecha y severidad. | Debe generar `earliest="11/11/2026..." latest="..."` y devolver los eventos CRITICAL. | ⬜ |
| **P4** | `"Analiza el hash 44d88612fea8a8f36de82e1278abb02f"` | Búsqueda por IOC y evaluación. | Debe generar `search index=main "44d88612..."` y mostrar el evento EICAR. | ⬜ |

---

## 🚨 BLOQUE 2: Pruebas Trampa (Edge Cases y Falsos Positivos)
*Para validar que el LLM no alucina y el sistema es seguro.*

| ID | Pregunta a realizar | Lo que prueba | Resultado Esperado | Estado |
| :--- | :--- | :--- | :--- | :--- |
| **P5** | `"Investiga la IP 8.8.8.8. ¿Por qué está en las alertas?"` | Falso positivo de red. | F.R.I.D.A.Y. debe consultar VirusTotal y decir que es inofensiva (DNS de Google). | ⬜ |
| **P6** | `"Dame los ataques de fuerza bruta de ayer a las 3 AM en falex"` | El "Vacío" (No alucinación). | Splunk devuelve 0 resultados y Ollama dice: "No hay registros, posiblemente no hubo ataque o falta ingesta". | ⬜ |
| **P7** | `"Analiza el dominio evil-domain.tld con la herramienta de Phishing"` | Uso de Threat Intel externa. | F.R.I.D.A.Y. usa PhishDestroy y responde si el dominio es malicioso o no. | ⬜ |

---

## 📝 Registro de Ejecución (Log de Pruebas)
*Copia y pega aquí la salida de la terminal de las pruebas que fallen para ajustar el sistema.*

**Fecha de prueba:** ____ / ____ / 2026
**Modelo LLM:** qwen2.5:3b
**Versión del RAG:** 2755 chars

- **Resultado P1:** [Pegar salida]
- **Resultado P2:** [Pegar salida]
- ...




| ID | Pregunta a realizar | Resultado Esperado | Estado |
| :--- | :--- | :--- | :--- |
| P1 | IP 185.229.227.28 | Correlación de IP maliciosa | ✅ PASSED |
| P2 | Vssadmin/Ransomware | Búsqueda con OR y análisis de 0 resultados | ✅ PASSED |
| P3 | Alertas críticas 11-11 | Filtro por fecha y severidad | ✅ PASSED |
| P4 | Hash EICAR | Identificación de falso positivo | ✅ PASSED |
| P5 | IP 8.8.8.8 | F.R.I.D.A.Y. consulta VirusTotal (falso positivo) | ✅ PASSED |
| P6 | Fuerza bruta (vacío) | No alucina, analiza ausencia de datos | ✅ PASSED |
| P7 | Dominio evil-domain.tld | F.R.I.D.A.Y. consulta PhishDestroy | ✅ PASSED |