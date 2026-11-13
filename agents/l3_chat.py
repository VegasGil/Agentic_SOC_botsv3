import os
import json
import re
import yaml
from openai import OpenAI
from tools.splunk_reader import fetch_splunk_alerts
from tools.defender_tool import obtener_evidencia
from tools.splunk_verdict_reader import ejecutar_consulta_spl
from tools.spl_query_generator import generar_consulta_spl

from agents.friday import friday, ejecutar_friday
from agents.edith import ejecutar_edith
from agents.karen import ejecutar_karen
from agents.vision import vigilante_splunk

def cargar_config_l3():
    ruta = os.path.join("config", "l3_chat.json")
    with open(ruta, "r", encoding="utf-8") as f:
        return json.load(f)

def cargar_config_splunk():
    ruta = os.path.join("config", "splunk_config.yaml")
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return {"default_index": "main", "available_indexes": []}

config_l3 = cargar_config_l3()
config_splunk = cargar_config_splunk()
default_index = config_splunk.get("default_index", "main")

client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

def iniciar_l3_chat():
    print(config_l3["welcome_message"])
    print(f"💡 [Config] Índice por defecto de Splunk: {default_index}")
    
    print("\n   [Sistema] Buscando alertas en Splunk...")
    
    try:
        fetch_splunk_alerts.run()
        with open("data/splunk_alerts.json", "r", encoding="utf-8") as f:
            alertas = json.load(f)
    except Exception as e:
        print(f"   ⚠️ [Aviso] No se pudieron cargar las alertas iniciales: {e}")
        alertas = []
    
    resumen_splunk = ""
    for i, a in enumerate(alertas, 1):
        fecha_raw = a.get('alertCreationTime') or a.get('firstEventTime') or a.get('lastEventTime')
        fecha = fecha_raw[:10] if fecha_raw else "Sin fecha"
        resumen_splunk += f"Alerta {i}: {a.get('title', '')} | Equipo: {a.get('computerDnsName', '')} | Gravedad: {a.get('severity', '')} | Fecha: {fecha}\n"

    en_menu_agentes = False
    palabras = config_l3.get("palabras_clave", {})

    while True:
        try:
            if en_menu_agentes:
                entrada = input("\n👉 Elige un número (1-7) o 'cancelar': ")
            else:
                entrada = input("\n👨‍💻 Tú: ")
                
            texto_lower = entrada.lower()
            if texto_lower in ["salir", "exit", "quit"]:
                break
            if texto_lower in ["cancelar", "no"]:
                if en_menu_agentes: 
                    en_menu_agentes = False
                    print("🤖 [Sistema] Modo cancelado. Volviendo al chat.")
                continue

            # ==========================================
            # 0. PREGUNTAS SOBRE ÍNDICES (DINÁMICO)
            # ==========================================
            if any(p in texto_lower for p in palabras.get("indices", [])):
                print("\n🤖 Analista: Actualmente tengo acceso a los siguientes índices en Splunk:")
                indices = config_splunk.get("available_indexes", [])
                if not indices:
                    print("   (No hay índices configurados en el archivo YAML).")
                else:
                    for i, idx in enumerate(indices, 1):
                        nombre = idx.get("name", "desconocido")
                        desc = idx.get("description", "Sin descripción")
                        print(f"   {i}. '{nombre}': {desc}")
                print(f"\n   (El índice por defecto es: '{default_index}')")
                continue
            
            # ==========================================
            # 1. MENÚ DE AGENTES (DINÁMICO)
            # ==========================================
            if en_menu_agentes:
                if texto_lower in ["1", "friday"]:
                    print("\n🚀 [Sistema] Despertando a F.R.I.D.A.Y...")
                    print(ejecutar_friday("falex", "Investigación desde Chat L3"))
                    en_menu_agentes = False
                    continue
                elif texto_lower in ["2", "edith"]:
                    print("\n🚀 [Sistema] Despertando a E.D.I.T.H...")
                    print(ejecutar_edith("falex"))
                    en_menu_agentes = False
                    continue
                elif texto_lower in ["3", "karen"]:
                    print("\n🚀 [Sistema] Despertando a K.A.R.E.N...")
                    print(ejecutar_karen("falex", "infraestructura"))
                    en_menu_agentes = False
                    continue
                elif texto_lower in ["4", "vision"]:
                    print("\n🚀 [Sistema] Despertando a V.I.S.I.O.N...")
                    print(vigilante_splunk("Visión, haz un barrido en falex"))
                    en_menu_agentes = False
                    continue
                elif texto_lower in ["5", "todo"]:
                    print("\n🚨 [Sistema] ALERTA MÁXIMA...")
                    ejecutar_friday("falex", "Alerta Máxima")
                    ejecutar_edith("falex")
                    ejecutar_karen("falex")
                    en_menu_agentes = False
                    continue
                elif texto_lower in ["6", "aspm"]:
                    print("\n🚀 [Sistema] Ejecutando motor ASPM (Trivy)...")
                    from tools.aspm_tool import scan_application_aspm
                    print(scan_application_aspm.run(target_path="."))
                    en_menu_agentes = False
                    continue
                elif texto_lower in ["7", "rbvm"]:
                    print("\n🚀 [Sistema] Ejecutando motor RBVM (Defender)...")
                    from tools.rbvm_enricher import prioritize_cves
                    from tools.kql_raw_fetcher import fetch_cves_raw
                    cves = fetch_cves_raw.run("falex")
                    print(prioritize_cves.run(cves))
                    en_menu_agentes = False
                    continue
                else:
                    print("⚠️ Opción no válida. Elige del 1 al 7.")
                    continue

            if any(p in texto_lower for p in palabras.get("menu", [])):
                print(config_l3["menu_agentes"]["title"])
                for k, v in config_l3["menu_agentes"]["options"].items():
                    print(f"  {v}")
                en_menu_agentes = True
                continue

            # ==========================================
            # 2. GENERAR Y EJECUTAR CONSULTA SPL (DINÁMICO)
            # ==========================================
            if any(p in texto_lower for p in palabras.get("informes", [])):
                print("   [Sistema] Analizando petición...")
                patron_fecha = re.search(r'(\d{2}-\d{2}-\d{2,4}|\d{4}-\d{2}-\d{2})', entrada)
                
                if patron_fecha:
                    fecha_raw = patron_fecha.group(0)
                    if len(fecha_raw.split('-')[0]) == 2:
                        partes = fecha_raw.split('-')
                        anio = partes[2] if len(partes[2]) == 4 else f"20{partes[2]}"
                        fecha_filtro = f"{anio}-{partes[1]}-{partes[0]}"
                    else:
                        fecha_filtro = fecha_raw
                    
                    print(f"   [Sistema] Filtrando por fecha: {fecha_filtro}")
                    resultado_splunk = ejecutar_consulta_spl.run(fecha_filtro=fecha_filtro)
                else:
                    print("   [Sistema] Generando consulta SPL dinámica...")
                    query_spl = generar_consulta_spl.run(entrada)
                    print(f"   [Sistema] Consulta SPL generada: {query_spl}")
                    resultado_splunk = ejecutar_consulta_spl.run(query_spl=query_spl)
                
                print(f"\n📊 [RESULTADO DE SPLUNK]:\n{resultado_splunk}")
                
                if "✅ Splunk devolvió" in resultado_splunk and "resultados" in resultado_splunk:
                    print("\n🧠 [Ollama analizando los resultados...]")
                    prompt_resumen = config_l3["prompts"]["resumen_datos"].format(resultado_splunk=resultado_splunk)
                    response = client.chat.completions.create(
                        model="qwen2.5:3b",
                        messages=[{"role": "user", "content": prompt_resumen}],
                        temperature=0.0
                    )
                    print(f"\n🤖 Analista: {response.choices[0].message.content}")
                elif "No se encontraron resultados" in resultado_splunk:
                    print("\n🧠 [Ollama evaluando la ausencia de resultados...]")
                    prompt_vacio = config_l3["prompts"]["sin_datos"].format(entrada=entrada)
                    response = client.chat.completions.create(
                        model="qwen2.5:3b",
                        messages=[{"role": "user", "content": prompt_vacio}],
                        temperature=0.0
                    )
                    print(f"\n🤖 Analista: {response.choices[0].message.content}")
                continue

            # ==========================================
            # 3. INVESTIGAR IP O URL (THREAT INTEL)
            # ==========================================
            if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', texto_lower) or re.search(r'[a-zA-Z0-9-]+\.(com|net|org|xyz|tld)', texto_lower):    
                print("   [Sistema] Detectada IP o URL. Despertando a F.R.I.D.A.Y...")
                respuesta_friday = friday.kickoff(entrada)
                print(f"\n🤖 F.R.I.D.A.Y.: {respuesta_friday}")
                continue

            # ==========================================
            # 4. DETECCIÓN DE ASPM Y RBVM
            # ==========================================
            if any(p in texto_lower for p in palabras.get("aspm", [])):
                print("   [Sistema] Ejecutando motor ASPM (Trivy)...")
                from tools.aspm_tool import scan_application_aspm
                resultado = scan_application_aspm.run(target_path=".")
                print(f"\n🤖 Analista (ASPM): {resultado}")
                continue

            if any(p in texto_lower for p in palabras.get("rbvm", [])):
                print("   [Sistema] Ejecutando motor RBVM (Defender)...")
                from tools.rbvm_enricher import prioritize_cves
                from tools.kql_raw_fetcher import fetch_cves_raw
                cves_json = fetch_cves_raw.run("falex")
                if not cves_json or cves_json.strip() == "":
                    print("\n🤖 Analista (RBVM): No se encontraron CVEs.")
                else:
                    print(f"\n🤖 Analista (RBVM): {prioritize_cves.run(cves_json)}")
                continue

            # ==========================================
            # 5. CONSULTA NORMAL (DEFENDER / SPLUNK)
            # ==========================================
            if any(p in texto_lower for p in palabras.get("defender", [])):
                print("   [Sistema] Solicitando evidencia a Defender...")
                datos_defender = obtener_evidencia("falex")
                if "No se encontraron" in datos_defender or "No hay archivos" in datos_defender:
                    print(f"\n🤖 Analista: {datos_defender}")
                    continue
                prompt_final = config_l3["prompts"]["defender"].format(datos_defender=datos_defender, entrada=entrada)
            else:
                prompt_final = config_l3["prompts"]["splunk_general"].format(resumen_splunk=resumen_splunk, entrada=entrada)

            print("🧠 [Ollama pensando...]")
            response = client.chat.completions.create(
                model="qwen2.5:3b",
                messages=[
                    {"role": "system", "content": config_l3["system_prompt"]},
                    {"role": "user", "content": prompt_final}
                ],
                temperature=0.0
            )
            
            print(f"\n🤖 Analista: {response.choices[0].message.content}")
            
        except KeyboardInterrupt:
            print("\n🤖 [L3 CHAT] Interrupción manual.")
            break
        except Exception as e:
            print(f"\n⚠️ Error: {e}")

if __name__ == "__main__":
    iniciar_l3_chat()