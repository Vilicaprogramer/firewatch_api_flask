import pandas as pd
from datetime import datetime
import psycopg2
import numpy as np

import pandas as pd
from datetime import datetime
import psycopg2
import uuid


def clean_data_ddos(archive_dic):
    df = pd.DataFrame([archive_dic])
    df.columns = df.columns.str.strip()

    df = df[['Destination Port', 'Flow Duration', 'Total Fwd Packets','Total Backward Packets','Flow Bytes/s','Flow Packets/s','Fwd Packet Length Mean','Fwd Packet Length Std','Min Packet Length','Max Packet Length','Flow IAT Mean','Flow IAT Std','SYN Flag Count','ACK Flag Count','Down/Up Ratio','Active Mean','Idle Mean','Label']]
    mapping = {
        "Web Attack ´?¢ Sql Injection": "Critical",
        "Web Attack ´?¢ XSS": "High",
        "Web Attack ´?¢ Brute Force": "Moderate",
        "BENIGN": "Benign"
    }
    df["Score"] = df["Label"].map(mapping)

    mapping2 = {
        "Web Attack ´?¢ Sql Injection": 3,
        "Web Attack ´?¢ XSS": 2,
        "Web Attack ´?¢ Brute Force": 1,
        "BENIGN": 0
    }
    df["Severity"] = df["Label"].map(mapping2)

    mapping3 = {
        "Critical": "Incidencia",
        "Moderate": "Alerta",
        "High": "Alerta",
        "Benign": "Info"
    }

    df["Tipo"] = df["Score"].map(mapping3)
    
    df = df.rename(columns={"Label": "Indicadores"})

    df["Indicadores"] = df["Indicadores"].str.replace("Web Attack ´?¢ ", "", regex=False)
    
    columns = [
    'Destination Port',
    'Estandar',
    'Description',
    'Ataques/CVEs tipicos',
    'Como proteger'
    ]

    datos = [
    [80, 'HTTP',
     'Tráfico web sin TLS. Expuesto a robo/manipulación de datos (MITM) y vulnerabilidades de aplicaciones web (XSS, SQLi, RCE) y del propio servidor.',
     'Fallos en frameworks/servidores web y módulos (p. ej., deserialización, path traversal).',
     'Redirigir 80→443, WAF, cabeceras seguras (HSTS/CSP), hardening del servidor, parches continuos y pruebas SAST/DAST.'],

    [53, 'DNS',
     'Resolución de nombres. Muy usado en ataques de envenenamiento de caché, spoofing, tunneling y amplificación DDoS.',
     'Vulnerabilidades en BIND/Unbound/dnsmasq; abuso de recursión abierta.',
     'Desactivar recursión pública, aplicar rate-limit, DNSSEC, listas de control de acceso, egress filtering para impedir túneles DNS.'],

    [443, 'HTTPS',
     'Web con TLS. Riesgo principal: mala configuración (protocolos/algoritmos débiles, certificados inválidos) además de las mismas vulnerabilidades de la app web que en 80.',
     'Downgrade/MITM si hay TLS obsoleto; fallos en librerías TLS y servidores.',
     'TLS 1.2/1.3, desactivar suites inseguras, HSTS, pinning si aplica, automatizar renovación de certificados, WAF y hardening.'],

    [36788, 'No estándar',
     'Puerto efímero no asociado a un servicio conocido.',
     'Uso por backdoors/C2 o exfiltración.',
     'Política de mínimo privilegio en firewall, bloquear si no se usa, monitorizar flujos inusuales y aplicar alertas SIEM.'],

    [4537, 'No estándar',
     'Puerto sin asignación común.',
     'Canales ocultos de malware, P2P o túneles.',
     'Egress filtering estricto, IDS/IPS, cerrar servicios no documentados y revisar binarios/servicios.'],

    [39717, 'No estándar',
     'Puerto efímero con tráfico alto no habitual.',
     'Escaneo, exfiltración o C2.',
     'Bloquear por defecto, permitir solo listas blancas, correlacionar con reputación IP y detectar patrones anómalos.'],

    [49836, 'No estándar',
     'Puerto efímero sin servicio documentado.',
     'Uso oportunista por malware/troyanos.',
     'Segmentación de red, EDR en endpoints, alertas por conexiones salientes persistentes.'],

    [51908, 'No estándar',
     'Puerto sin servicio conocido.',
     'Comunicaciones P2P o botnets.',
     'Bloqueo si no está en catálogo, inspección profunda (DPI) y reglas de detección de beaconing.'],

    [49256, 'No estándar',
     'Actividad inusual si actúa como servidor.',
     'Escaneo y canales de mando y control.',
     'Registrar y alertar scans, limitar exposición, revisar procesos que hacen bind a este puerto.'],

    [54426, 'No estándar',
     'Puerto efímero similar a otros altos.',
     'RATs y túneles de datos.',
     'Bloquear por defecto, listas blancas, correlación con destinos/horarios y revisión de integridad del host.']
    ]

    df2 = pd.DataFrame(datos, columns=columns)

    df["Destination Port"] = df["Destination Port"].astype(int)
    df2["Destination Port"] = df2["Destination Port"].astype(int)

    df = pd.merge(df, df2, on="Destination Port", how="left")


    df["ddos_id"] = [(uuid.uuid4().int) %1_000_000]
    

    now = datetime.now()
    df["Date"] = now.date()
    df["Time"] = now.strftime("%H:%M:%S")

    
        
    conn = psycopg2.connect(
    dbname="desafiogrupo1",
    user="desafiogrupo1_user",
    password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
    host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
    port="5432"
    )

    


    cur = conn.cursor()
    records = [
        {
            "id": row['ddos_id'],
            "company_id": 1,
            "type": row["Tipo"],
            "indicators": row["Indicadores"],
            "severity": row["Severity"],
            "date": row["Date"],
            "time": row["Time"],
            "actions_taken": 1
        }   
        for _, row in df.iterrows()
    ]
    

    cur.executemany("""
        INSERT INTO logs (id, company_id, type, indicators, severity, date, time,actions_taken)
        VALUES (%(id)s, %(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
        """, records)



    
    records_2 = [
            {
            'log_id':  row['ddos_id'],
            'Destination Port': row['Destination Port'],
            'Flow Duration': row['Flow Duration'], 
            'Total Fwd Packets': row['Total Fwd Packets'],
            'Total Backward Packets': row['Total Backward Packets'],
            'Flow Bytes/s':row['Flow Bytes/s'] ,
            'Flow Packets/s': row['Flow Packets/s'],
            'Fwd Packet Length Mean': row['Fwd Packet Length Mean'],
            'Fwd Packet Length Std': row['Fwd Packet Length Std'],
            'Min Packet Length':row['Min Packet Length'],
            'Max Packet Length': row['Max Packet Length'],
            'Flow IAT Mean':row['Flow IAT Mean'] ,
            'Flow IAT Std': row['Flow IAT Std'],
            'SYN Flag Count': row['SYN Flag Count'],
            'ACK Flag Count':row['ACK Flag Count'] ,
            'Down/Up Ratio': row['Down/Up Ratio'],
            'Active Mean':row['Active Mean'] ,
            'Idle Mean': row['Idle Mean'],
            'Score':row['Score'],
            'Severity': row['Severity'],
            'Tipo': row['Tipo'],
            'Indicadores': row['Indicadores'],
            'Estandar':row['Estandar'] ,
            'Description': row['Description'],
            'Ataques/CVEs tipicos': row['Ataques/CVEs tipicos'],
            'Como proteger': row['Como proteger'],
            'date': row['Date'],
            'time': row['Time']

        }
            for _, row in df.iterrows()
        ]

    cur.executemany("""
        INSERT INTO ddos (
            "log_id", "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Min Packet Length", "Max Packet Length", "Flow IAT Mean", "Flow IAT Std",
            "SYN Flag Count", "ACK Flag Count", "Down/Up Ratio", "Active Mean", "Idle Mean",
            "Indicadores", "Score", "Severity", "Tipo", "Estandar", "Description",
            "Ataques/CVEs tipicos", "Como proteger", "date", "time"
        )
        VALUES (
            %(log_id)s, %(Destination Port)s, %(Flow Duration)s, %(Total Fwd Packets)s, %(Total Backward Packets)s,
            %(Flow Bytes/s)s, %(Flow Packets/s)s, %(Fwd Packet Length Mean)s, %(Fwd Packet Length Std)s,
            %(Min Packet Length)s, %(Max Packet Length)s, %(Flow IAT Mean)s, %(Flow IAT Std)s,
            %(SYN Flag Count)s, %(ACK Flag Count)s, %(Down/Up Ratio)s, %(Active Mean)s, %(Idle Mean)s,
            %(Indicadores)s, %(Score)s, %(Severity)s, %(Tipo)s, %(Estandar)s, %(Description)s,
            %(Ataques/CVEs tipicos)s, %(Como proteger)s, %(date)s, %(time)s
        )
    """, records_2)


    conn.commit()
    cur.close()
    conn.close()



# ================  LOGIN  ====================
import pandas as pd
import numpy as np
import psycopg2
from datetime import datetime
import requests
import time
from dotenv import load_dotenv
import os
load_dotenv()
API_KEY = "bc75c37a0bd14e9bfcb283cfa464e290d125218acc693b1193c6754220a38fb74403006313b80bd7"
CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Accept": "application/json", "Key": API_KEY}
DB_CONF = {
    "dbname": "desafiogrupo1",
    "user": "desafiogrupo1_user",
    "password": "g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
    "host": "dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
    "port": "5432"
}
# ----------------- 1) Limpieza -----------------
def clean_data_login2(archive_dic):
    df = pd.DataFrame([archive_dic])
    df.columns = df.columns.str.strip()
    ts = pd.to_datetime(df.get("Login Timestamp"), errors="coerce", utc=True)
    ts = ts.apply(lambda x: x.replace(year=2025) if pd.notna(x) else x)
    df["Date"] = ts.dt.date
    df["Time"] = ts.dt.strftime("%H:%M:%S")
    ls = df.get("Login Successful", pd.Series([False])).fillna(False).astype(bool)
    ia = df.get("Is Attack IP", pd.Series([False])).fillna(False).astype(bool)
    iat = df.get("Is Account Takeover", pd.Series([False])).fillna(False).astype(bool)
    rojo = (ls) & (ia) & (iat)
    naranja = (ls) & (ia) & (~iat)
    amarillo = (~ls) & (ia) & (~iat)
    blanco = (ls) & (~ia) & (~iat)
    df["Severity"] = np.select([rojo, naranja, amarillo, blanco], [3, 2, 1, 0], default=1).astype(int)
    df["Tipo"] = np.select(
        [df["Severity"].eq(3), df["Severity"].isin([1,2]), df["Severity"].eq(0)],
        ["Incidencia", "Alerta", "Info"], default="Info"
    )
    df["Indicadores"] = np.select(
        [df["Severity"].eq(3), df["Severity"].eq(2), df["Severity"].eq(1), df["Severity"].eq(0)],
        ["Robo de credenciales", "Cuenta comprometida", "Ataque fallido", "Login válido"], default=""
    )
    return df
# ----------------- 2) Enriquecimiento -----------------
def check_ip_info(ip, pause=0.5):
    try:
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
        r = requests.get(CHECK_URL, headers=HEADERS, params=params)
        r.raise_for_status()
        data = r.json().get("data", {})
        info = {
            "ipAddress": data.get("ipAddress"),
            "countryCode": data.get("countryCode"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "lastReportedAt": data.get("lastReportedAt"),
            "usageType": data.get("usageType"),
            "domain": data.get("domain"),
            "totalReports": data.get("totalReports")
        }
        time.sleep(pause)
        return info
    except Exception as e:
        print(f"Error con {ip}: {e}")
        return {}
def enrich_login_record(record_dict):
    df_enriq = pd.DataFrame([record_dict])
    ip = check_ip_info(df_enriq.iloc[0]["IP Address"])
    if ip:
        api_info = check_ip_info(ip["ipAddress"])
        for k,v in api_info.items():
            if k != "ipAddress":
                df_enriq[k] = v
    return df_enriq
# ----------------- 3) Inserción con prints de debug -----------------
def insert_into_db_debug(df_clean, df_enriq):
    try:
        print("Conectando a PostgreSQL...")
        conn = psycopg2.connect(**DB_CONF)
        cur = conn.cursor()
        print("Conexión establecida.")
        # Insertar en logs
        row = df_clean.iloc[0]
        record_logs = {
            "company_id": 1,
            "type": row["Tipo"],
            "indicators": row["Indicadores"],
            "severity": int(row["Severity"]),
            "date": row["Date"],
            "time": row["Time"],
            "actions_taken": 1
        }
        print("Datos a insertar en logs:", record_logs)
        insert_logs = """
        INSERT INTO logs (company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
        RETURNING id;
        """
        cur.execute(insert_logs, record_logs)
        log_id = cur.fetchone()[0]
        print("ID generado en logs:", log_id)
        # Insertar en login
        row_enr = df_enriq.iloc[0]
        record_login = {
                "log_id": int(log_id),
                "login_timestamp": None if pd.isna(row_enr.get("Login Timestamp")) else pd.to_datetime(row_enr.get("Login Timestamp")),
                "user_id": None if pd.isna(row_enr.get("User ID")) else int(row_enr.get("User ID")),
                "round_trip_time": None if pd.isna(row_enr.get("Round-Trip Time [ms]")) else float(row_enr.get("Round-Trip Time [ms]")),
                "ip_address": None if pd.isna(row_enr.get("IP Address")) else str(row_enr.get("IP Address")),
                "country": None if pd.isna(row_enr.get("Country")) else str(row_enr.get("Country")),
                "asn": None if pd.isna(row_enr.get("ASN")) else int(row_enr.get("ASN")),
                "user_agent": None if pd.isna(row_enr.get("User Agent String")) else str(row_enr.get("User Agent String")),
                "country_code": None if pd.isna(row_enr.get("countryCode")) else str(row_enr.get("countryCode")),
                "abuse_confidence_score": None if pd.isna(row_enr.get("abuseConfidenceScore")) else int(row_enr.get("abuseConfidenceScore")),
                "last_reported_at": None if pd.isna(row_enr.get("lastReportedAt")) else pd.to_datetime(row_enr.get("lastReportedAt")),
                "usage_type": None if pd.isna(row_enr.get("usageType")) else str(row_enr.get("usageType")),
                "domain": None if pd.isna(row_enr.get("domain")) else str(row_enr.get("domain")),
                "total_reports": None if pd.isna(row_enr.get("totalReports")) else int(row_enr.get("totalReports")),
        }
        print("Datos a insertar en login:", record_login)
        insert_login = """
        INSERT INTO login (
            log_id, login_timestamp, user_id, round_trip_time,
            ip_address, country, asn, user_agent,
            country_code, abuse_confidence_score, last_reported_at,
            usage_type, domain, total_reports
        )
        VALUES (
            %(log_id)s, %(login_timestamp)s, %(user_id)s, %(round_trip_time)s,
            %(ip_address)s, %(country)s, %(asn)s, %(user_agent)s,
            %(country_code)s, %(abuse_confidence_score)s, %(last_reported_at)s,
            %(usage_type)s, %(domain)s, %(total_reports)s
        )
        RETURNING id;
        """
        cur.execute(insert_login, record_login)
        login_id = cur.fetchone()[0]
        print("ID generado en login:", login_id)
        conn.commit()
        cur.close()
        conn.close()
        print(":marca_de_verificación_blanca: Inserción completada correctamente.")
    except Exception as e:
        print(f":x: Error insertando en PostgreSQL: {e}")

def tres_en_uno(dict):
    df_clean = clean_data_login2(dict)
    df_enriq = enrich_login_record(dict)
    insert_into_db_debug(df_clean, df_enriq)