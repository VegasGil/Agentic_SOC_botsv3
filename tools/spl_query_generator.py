import os
import re
import yaml
from crewai.tools import tool
from openai import OpenAI

@tool("Generar Consulta SPL para Splunk")
def generar_consulta_spl(pregunta: str) -> str:
    """Traduce una pregunta en lenguaje natural a una consulta SPL válida usando RAG y configuración YAML."""
    
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    
    # ==========================================================
    # 1. LEER LA CONFIGURACIÓN DE ÍNDICES (YAML)
    # ==========================================================
    ruta_config = os.path.join("config", "splunk_config.yaml")
    try:
        with open(ruta_config, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            default_index = config.get("default_index", "main")
            indices_disponibles = ", ".join([idx["name"] for idx in config.get("available_indexes", [])])
    except Exception as e:
        print(f"   ⚠️ [Config] No se pudo leer splunk_config.yaml: {e}")
        default_index = "main"
        indices_disponibles = "main"

    # ==========================================================
    # 2. CARGAR EL RAG DE EJEMPLOS
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
    # 3. CONSTRUIR EL PROMPT
    # ==========================================================
    prompt = f"""Eres un experto en Splunk SPL. Tu tarea es elegir la consulta SPL MÁS PARECIDA del catálogo de ejemplos y devolverla TAL CUAL.

ÍNDICES DISPONIBLES EN ESTE SPLUNK: {indices_disponibles}
ÍNDICE POR DEFECTO: {default_index}

CATÁLOGO DE CONSULTAS VALIDADAS:
{ejemplos}

REGLAS ESTRICTAS:
1. Si la pregunta menciona un hash, IP, event_id o dominio → usa `search index={default_index} "texto"`.
2. Si la pregunta menciona un índice específico (ej. "botsv3") → usa ese índice.
3. Si la pregunta menciona una fecha → usa el patrón con earliest/latest y el índice por defecto.
4. NUNCA inventes campos como `_name`, `_internal.Host`, `table` que no estén en el catálogo.
5. SIEMPRE cierra las comillas dobles que abras.
6. Devuelve SOLO la consulta SPL, sin explicaciones ni markdown. NO uses backticks (`).

PREGUNTA DEL USUARIO: "{pregunta}"

CONSULTA SPL:"""
    
    # ==========================================================
    # 4. LLAMAR A OLLAMA
    # ==========================================================
    try:
        response = client.chat.completions.create(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0
        )
        spl_query = response.choices[0].message.content.strip()
        
        # ==========================================================
        # 5. LIMPIEZA PROFUNDA (quitamos backticks, markdown, comillas)
        # ==========================================================
        spl_query = spl_query.replace("```spl", "").replace("```SPL", "").replace("```", "").strip()
        spl_query = spl_query.replace("`", "")
        spl_query = spl_query.strip('"').strip("'").strip()
        spl_query = re.sub(r'\s+', ' ', spl_query).strip()
        
        # ==========================================================
        # 6. VALIDACIONES (en orden)
        # ==========================================================
        
        # 6.1 Si la consulta YA empieza por "search", no la envolvemos
        if not spl_query.startswith("search"):
            spl_query = f'search index={default_index} "{spl_query}"'
        
        # 6.2 Eliminar campos inventados
        campos_inventados = ["_internal.Host", "_internal.", "| table _name", "table _internal"]
        for campo in campos_inventados:
            if campo in spl_query:
                m = re.search(r'"([^"]+)"', spl_query)
                if m:
                    spl_query = f'search index={default_index} "{m.group(1)}"'
                else:
                    spl_query = f'search index={default_index} | head 20'
                break
        
        # 6.3 Balancear comillas (si hay impares, cerramos al final)
        if spl_query.count('"') % 2 != 0:
            spl_query = spl_query.rstrip() + '"'
        
        # 6.4 Validación final: si hay doble "search index=main" anidado, lo limpiamos
        if spl_query.count("search index=") > 1:
            m = re.search(r'"([^"]+)"', spl_query)
            if m:
                spl_query = f'search index={default_index} "{m.group(1)}"'

        # ==========================================================
        # 7. TRUCO SENIOR: Convertir campos específicos a texto general
        # ==========================================================
        spl_query = re.sub(r'\w+="([^"]+)"', r'"\1"', spl_query)
        spl_query = re.sub(r"\w+='([^']+)'", r'"\1"', spl_query)
        
        # Aseguramos que siempre tenga un límite (head)
        if "| head" not in spl_query:
            spl_query += " | head 50"
            
        # ==========================================================
        # 8. SALVAVIDAS FINAL (Si Ollama se vuelve loco)
        # ==========================================================
        if len(spl_query) < 15 or spl_query == f'search index={default_index} ""' or spl_query == f'search index={default_index} | head 50':
            palabras = [p for p in pregunta.split() if len(p) > 3]
            if palabras:
                ioc_probable = max(palabras, key=len).strip('"').strip("'")
                spl_query = f'search index={default_index} "{ioc_probable}" | head 50'
            else:
                spl_query = f'search index={default_index} | head 20'
                
        return spl_query
        
    except Exception as e:
        return f'search index={default_index} error="{e}"'