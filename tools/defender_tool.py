import glob
import json
import os

def obtener_evidencia(equipo: str = "falex", fecha_filtro: str = None):
    try:
        archivos = glob.glob('data/azure_dump_*.json')
        if not archivos:
            return "No hay archivos de evidencia en data/."
            
        evidencia_total = ""
        encontrados = 0
        
        # Leemos TODOS los archivos de la carpeta
        for archivo in archivos:
            with open(archivo, 'r', encoding='utf-8') as f:
                try:
                    datos = json.load(f)
                except:
                    continue 
                
            for item in datos:
                comando = item.get('ProcessCommandLine')
                # Si no hay comando, saltamos
                if not comando:
                    continue
                    
                usuario = item.get('AccountName', 'N/A')
                fecha_evento = item.get('Timestamp', 'N/A')
                
                # Si hay filtro de fecha, comprobamos que coincida
                if fecha_filtro and fecha_filtro not in fecha_evento:
                    continue
                
                evidencia_total += f"Usuario: {usuario} | Comando: {comando} | Fecha: {fecha_evento}\n"
                encontrados += 1
                
        if encontrados > 0:
            # Quitamos duplicados por si el mismo comando se guardó en varios archivos
            lineas_unicas = list(set(evidencia_total.splitlines()))
            return "\n".join(lineas_unicas)
            
        return "No se encontraron comandos de procesos en ningún archivo de la carpeta data/."
        
    except Exception as e:
        return f"Error al leer la evidencia: {e}"