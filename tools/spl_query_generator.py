import os
import re
from crewai.tools import tool
from openai import OpenAI

@tool("Generar Consulta SPL para Splunk")
def generar_consulta_spl(pregunta: str) -> str:
    """Traduce una pregunta en lenguaje natural a una consulta SPL válida para Splunk usando un catálogo de ejemplos validados."""
    
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    
    # ==========================================================
    # 1. CARGAR EL RAG DE EJEMPLOS
    # ==========================================================
    ruta_ejemplos = os.path.join("knowledge", "l3", "spl_examples.md")
    try:
        with open(ruta_ejemplos, "r", encoding="utf-8") as f:
            ejemplos = f.read()
        print(f"   [RAG] Ejemplos cargados: {len(ejemplos)} chars")
    except Exception as e:
        print(f"   [RAG] ⚠️ ERROR cargando ejemplos: {e}")
        ejemplos = "(No hay ejemplos cargados, usa consultas simples)"
    
    # ==========================================================
    # 2. CONSTRUIR EL PROMPT
    # ==========================================================
    prompt = f"""Eres un experto en Splunk SPL. Tu tarea es elegir la consulta SPL MÁS PARECIDA del catálogo de ejemplos y devolverla TAL CUAL.

CATÁLOGO DE CONSULTAS VALIDADAS:
{ejemplos}

REGLAS ESTRICTAS:
1. Si la pregunta menciona un hash, IP, event_id o dominio → usa el patrón "Búsqueda por Hash/IP/Event ID" (solo `search index=main "texto"`).
2. Si la pregunta menciona una fecha (ej. 11-11-2026) → usa el patrón "Búsqueda por Fecha" con earliest/latest.
3. Si la pregunta menciona un equipo (falex, etc.) → usa el patrón "Búsqueda por Equipo".
4. Si la pregunta menciona un agente (FRIDAY, KAREN, Nirvana) → usa el patrón "Búsqueda por Agente".
5. Si menciona veredictos → usa el sourcetype nirvana:secops:verdict.
6. Si menciona un incidentId o una alerta específica → usa el patrón de "Incidente Completo" o "Alerta Específica".
7. NUNCA inventes campos como `_name`, `_internal.Host`, `table` que no estén en el catálogo.
8. SIEMPRE cierra las comillas dobles que abras.
9. Devuelve SOLO la consulta SPL, sin explicaciones ni markdown. NO uses backticks (`).

PREGUNTA DEL USUARIO: "{pregunta}"

CONSULTA SPL (copia el patrón del catálogo y sustituye el valor):"""
    
    # ==========================================================
    # 3. LLAMAR A OLLAMA
    # ==========================================================
    try:
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0
        )
        spl_query = response.choices[0].message.content.strip()
        
        # ==========================================================
        # 4. LIMPIEZA PROFUNDA (quitamos backticks, markdown, comillas)
        # ==========================================================
        spl_query = spl_query.replace("```spl", "").replace("```SPL", "").replace("```", "").strip()
        spl_query = spl_query.replace("`", "")
        spl_query = spl_query.strip('"').strip("'").strip()
        spl_query = re.sub(r'\s+', ' ', spl_query).strip()
        
        # ==========================================================
        # 5. VALIDACIONES (en orden)
        # ==========================================================
        
        # 5.1 Si la consulta YA empieza por "search", no la envolvemos
        if not spl_query.startswith("search"):
            spl_query = f'search index=main "{spl_query}"'
        
        # 5.2 Eliminar campos inventados
        campos_inventados = ["_internal.Host", "_internal.", "| table _name", "table _internal"]
        for campo in campos_inventados:
            if campo in spl_query:
                m = re.search(r'"([^"]+)"', spl_query)
                if m:
                    spl_query = f'search index=main "{m.group(1)}"'
                else:
                    spl_query = 'search index=main | head 20'
                break
        
        # 5.3 Balancear comillas (si hay impares, cerramos al final)
        if spl_query.count('"') % 2 != 0:
            spl_query = spl_query.rstrip() + '"'
        
        # 5.4 Validación final: si hay doble "search index=main" anidado, lo limpiamos
        if spl_query.count("search index=main") > 1:
            m = re.search(r'"([^"]+)"', spl_query)
            if m:
                spl_query = f'search index=main "{m.group(1)}"'

        # ==========================================================
        # 6. TRUCO SENIOR: Convertir campos específicos a texto general
        # ==========================================================
        # Si Ollama escribió ipAddress="1.2.3.4" o incidentId="788", lo convertimos a "1.2.3.4" o "788"
        spl_query = re.sub(r'\w+="([^"]+)"', r'"\1"', spl_query)
        spl_query = re.sub(r"\w+='([^']+)'", r'"\1"', spl_query)
        
        # Aseguramos que siempre tenga un límite (head)
        if "| head" not in spl_query:
            spl_query += " | head 50"
            
        # ==========================================================
        # 7. SALVAVIDAS FINAL (Si Ollama se vuelve loco)
        # ==========================================================
        if len(spl_query) < 15 or spl_query == 'search index=main ""' or spl_query == 'search index=main | head 50':
            palabras = [p for p in pregunta.split() if len(p) > 3]
            if palabras:
                ioc_probable = max(palabras, key=len).strip('"').strip("'")
                spl_query = f'search index=main "{ioc_probable}" | head 50'
            else:
                spl_query = 'search index=main | head 20'
                
        return spl_query
        
    except Exception as e:
        return f'search index=main error="{e}"'