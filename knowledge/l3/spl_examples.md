# Catálogo de Consultas SPL Validadas para Agentic-SOC

## Formato: PREGUNTA | CONSULTA_SPL

### Búsqueda por Hash
- "busca el hash 44d886..." | `search index=main "44d886..." `
- "investiga el hash abc123" | `search index=main "abc123"`
- "busca IOC hash xyz" | `search index=main "xyz"`

### Búsqueda por Event ID
- "busca el evento evt-eicar-malware" | `search index=main "evt-eicar-malware"`
- "dame el event_id evt-real-malware" | `search index=main "evt-real-malware"`

### Búsqueda por IP (Texto general)
- "busca la IP 185.229.227.28" | `search index=main "185.229.227.28"`
- "investiga la ip 8.8.8.8" | `search index=main "8.8.8.8"`

### Búsqueda con OR (Palabras alternativas)
- "busca vssadmin o ransomware en falex" | `search index=main "falex" (vssadmin OR ransomware) | head 50`
- "malware o mineria en falex" | `search index=main "falex" (malware OR mineria OR xmrig) | head 50`

### Búsqueda de IPs
- "cuales son las ip atacante" | `search index=main "185.229.227.28" OR "8.8.8.8"`
- "dame las ips" | `search index=main ipAddress=* | head 50`
- "reporte de ips" | `search index=main | rex field=_raw "(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" | stats count by ip | head 50`

### Búsqueda por Fecha
- "informes del 11-11-2026" | `search index=main earliest="2026-11-11:00:00:00" latest="2026-11-11:23:59:59" | head 50`
- "dame los reportes del 12-11-2026" | `search index=main earliest="2026-11-12:00:00:00" latest="2026-11-12:23:59:59" | head 50`

### Búsqueda por Equipo
- "informes del equipo falex" | `search index=main "falex" | head 50`
- "dame reportes de falex" | `search index=main "falex" | head 50`

### Búsqueda por Agente (K.A.R.E.N. / KAREN)
- "reportes de K.A.R.E.N." | `search index=main source_agent="K.A.R.E.N." | head 50`
- "informes de K.A.R.E.N." | `search index=main source_agent="K.A.R.E.N." | head 50`
- "dame los reportes de K.A.R.E.N." | `search index=main source_agent="K.A.R.E.N." | head 50`
- "informes de KAREN" | `search index=main source_agent="K.A.R.E.N." | head 50`

### Búsqueda por Agente (F.R.I.D.A.Y. / FRIDAY)
- "reportes de F.R.I.D.A.Y." | `search index=main source_agent="F.R.I.D.A.Y." | head 50`
- "informes de F.R.I.D.A.Y." | `search index=main source_agent="F.R.I.D.A.Y." | head 50`

### Búsqueda por Agente (E.D.I.T.H. / EDITH)
- "reportes de E.D.I.T.H." | `search index=main source_agent="E.D.I.T.H." | head 50`
- "informes de E.D.I.T.H." | `search index=main source_agent="E.D.I.T.H." | head 50`
### Ver Veredictos (los que genera la IA)
- "veredictos de Nirvana" | `search index=main sourcetype="nirvana:secops:verdict" | head 50`
- "dame los veredictos" | `search index=main sourcetype="nirvana:secops:verdict" | head 50`

### Últimos eventos (sin filtro)
- "dame los últimos eventos" | `search index=main | head 20`
- "últimas alertas" | `search index=main | head 20`

### Búsqueda por Severidad
- "alertas críticas" | `search index=main severity="CRITICAL" | head 50`
- "alertas de severidad alta" | `search index=main severity="HIGH" | head 50`

### Búsqueda combinada
- "malware en falex" | `search index=main "falex" "malware" | head 50`
- "eicar en falex" | `search index=main "falex" "eicar" | head 50`

### Búsqueda por Incidente Completo (Defender)
- "Dame el incidente 788" | `search index=main incidentId=788 | head 50`
- "Analiza el incidente 788 de falex" | `search index=main "falex" incidentId=788 | head 50`

### Búsqueda por Alerta Específica
- "Busca la alerta Executable permission added to file" | `search index=main "Executable permission added to file" | head 50`
- "Dame las alertas de CryptoMiner" | `search index=main "CryptoMiner" | head 50`
- "Muestra las alertas de EICAR" | `search index=main "EICAR" | head 50`

### botv3

### Búsqueda en el Dataset BOTS v3 (Splunk Enterprise - Puerto 8001)
- "Busca PowerShell sospechoso en BOTS" | `search index=botsv3 sourcetype="xmlwineventlog" "powershell" | head 50`
- "Busca peticiones web sospechosas en BOTS" | `search index=botsv3 sourcetype="stream:http" | head 50`
- "Busca ataques de fuerza bruta en BOTS" | `search index=botsv3 "failed password" | head 50`
- "Busca el ataque a Apache Struts" | `search index=botsv3 "struts" | head 50`