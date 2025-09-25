# FIREWATCH API (Flask)

API en Flask para ingestión y visualización de eventos de **DDOS**, **Login** (con enriquecimiento AbuseIPDB) y (opcional) **Phishing**. Incluye endpoints para **gráficas** (Plotly), generación de **PDFs** y un **logger en segundo plano** que simula tráfico a partir de datasets públicos.

> La documentación detallada (Word) con explicación de módulos y diagrama de BD está en:  
> **`Documentacion_Firewatch_API.docx`**.

---

## ✨ Funcionalidades

- **EndPoints de visualización** (JSON Plotly) para DDOS/Phishing/Login.
- **Generación de informes PDF**: login, ddos y phishing.
- **Logger en segundo plano** para alimentar la base con datos de ejemplo.
- **Persistencia en PostgreSQL** (tablas: `logs`, `login`, `ddos`, `phishing`…).
- **Despliegue en Render.com** con `gunicorn`.

---

## 🗂 Estructura del proyecto

```
FIREWATCH_API_FLASK/
├─ app.py                   # API Flask: endpoints, gráficos, PDFs, logger BG
├─ limpieza_datos.py        # Pipelines de limpieza/enriquecimiento/inserción
├─ render.yaml              # Config Render (servicio web)
└─ requirements.txt         # Dependencias
```

---

## ⚙️ Requisitos

- Python 3.11 (sugerido 3.11.8)
- PostgreSQL accesible (variables de entorno abajo)
- (Opcional) Claves API:
  - **AbuseIPDB** para enriquecimiento de IPs (Login)
  - **VirusTotal** (bloque de phishing está comentado por ahora)

---

## 🔐 Variables de entorno

Crea un `.env` (para local) o configura en tu proveedor (Render):

```bash
# Base de datos
DB_NAME=desafiogrupo1
DB_USER=desafiogrupo1_user
DB_PASSWORD=xxxxxxxxxxxxxxxxxxxxxxxxxxxx
DB_HOST=dpg-xxxxx.oregon-postgres.render.com
DB_PORT=5432

# APIs (si aplican)
ABUSEIPDB_API_KEY=tu_api_key_abuseipdb
VT_API_KEY=tu_api_key_virustotal
```

> En `app.py` se leen las credenciales de BD con `os.environ` (función `get_connection()`).
> En `limpieza_datos.py` hay claves “hardcodeadas”; **mueve esas claves a variables de entorno** antes de producción.

---

## 🧰 Instalación y ejecución local

```bash
python -m venv .venv
source .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install --upgrade pip
pip install -r requirements.txt

# Ejecutar
python app.py
# Servirá en http://0.0.0.0:5000  (DEBUG=True)
```

### Notas
- Si tu sistema da problemas compilando `psycopg2`, usa:
  ```
  pip uninstall psycopg2 -y && pip install psycopg2-binary==2.9.9
  ```
- En Windows, puede requerir `Build Tools` si decides compilar `psycopg2` normal.

---

## ☁️ Despliegue en Render.com

1. Repositorio con `render.yaml`, `app.py`, `requirements.txt`.  
2. Crear **Web Service** desde el repo.
3. Asegurar:
   - `PYTHON_VERSION=3.11.8` (ya está en `render.yaml`).
   - **Start command**: `gunicorn app:app --bind 0.0.0.0:$PORT`
   - Variables de entorno: `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, etc.
4. Plan *free* hiberna: el **logger en segundo plano** se detendrá al dormir. Para tareas continuas, usar **Worker** o **Cron Jobs** de Render.

---

## 📡 Endpoints

### 1) Logger en segundo plano
- `POST /start-logging`  
  Inicia un hilo que toma registros aleatorios de dos datasets S3 (login y ddos) y los inserta usando `malware_type_detection()` → `clean_data_ddos` o `tres_en_uno`.
- `POST /stop-logging`  
  Detiene el hilo.

**Respuesta típica**
```json
{"status": "logging started"}
```

### 2) Gráficas (Plotly JSON)

- `GET /grafica_ddos`  
  Agrupa `logs` por `indicators IN ('BENIGN','XSS','Brute Force','Sql Injection')`
- `GET /grafica_phishing`  
  Agrupa `indicators IN ('Correo seguro','Posible phishing')`
- `GET /grafica_login`  
  Agrupa `indicators IN ('Robo de credenciales','Cuenta comprometida','Ataque fallido','Login válido')`

**Respuesta**: objeto Plotly (usar directamente en el front con `Plotly.react`/`Plot`).

### 3) PDFs

- `POST /download_pdf_login`  
  **Body (JSON)**:  
  `log_id, login_timestamp, user_id, round_trip_time, ip_address, country, asn, user_agent, country_code, abuse_confidence_score, last_reported_at, usage_type, domain, total_reports`  
  **Respuesta:** archivo PDF (descarga).

- `POST /download_pdf_ddos`  
  **Body (JSON)**:  
  métricas de flujo + enriquecimiento por puerto:  
  `Logs id, Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Flow Bytes/s, Flow Packets/s, Fwd Packet Length Mean, Fwd Packet Length Std, Min Packet Length, Max Packet Lengths, Flow IAT Mean, Flow IAT Std, SYN Flag Count, ACK Flag Count, Down/Up Ratio, Active Mean, Idle Mean, Indicadores, Score, Severity, Tipo, Estandar, Description, Ataques/CVEs tipicos, Como proteger, Date, Time`  
  **Respuesta:** PDF.

- `POST /download_pdf_phishing`  
  **Body (JSON)**:  
  `logs_id, url, status, malicious, suspicious, undetected, harmless, timeout, whois, tags, dns_records, last_dns_records_date, registrar, expiration_date, tld, issuer, subject_CN, cert_not_before, cert_not_after, cert_key_size, thumbprint_sha256, reputation, popularity_ranks, jarm, categories`  
  **Respuesta:** PDF.

#### Ejemplo `curl` (login)
```bash
curl -X POST http://localhost:5000/download_pdf_login   -H "Content-Type: application/json"   -d '{
    "log_id": 123,
    "login_timestamp": "2025-08-01T12:34:56Z",
    "user_id": 42,
    "round_trip_time": 120.5,
    "ip_address": "203.0.113.10",
    "country": "US",
    "asn": 13335,
    "user_agent": "Mozilla/5.0",
    "country_code": "US",
    "abuse_confidence_score": 5,
    "last_reported_at": "2025-07-15T20:00:00Z",
    "usage_type": "Data Center/Web Hosting/Transit",
    "domain": "example.com",
    "total_reports": 10
  }' --output Informe_123.pdf
```

---

## 🧪 Pipelines y tablas

### DDOS (`clean_data_ddos`)
- Normaliza columnas de flujo, mapea `Label → Score/Severity/Tipo`, y **enriquece por puerto** (`Estandar`, `Description`, `Ataques/CVEs tipicos`, `Como proteger`).
- Inserta:
  - `logs` (id = `ddos_id`)  
  - `ddos` (detalle métrico + enriquecimiento, `log_id` = `ddos_id`)

### Login (`tres_en_uno`)
- `clean_data_login2`: Severidad/Tipo/Indicadores a partir de `Login Successful`, `Is Attack IP`, `Is Account Takeover`.
- `enrich_login_record`: Contra **AbuseIPDB** (countryCode, abuseConfidenceScore…).
- Inserta:
  - `logs` (RETURNING id)
  - `login` (referencia `log_id` anterior)

### Phishing (comentado por ahora)
- Clasificador heurístico (`Correo seguro`/`Posible phishing`).
- Enriquecimiento con **VirusTotal** (`whois`, `dns_records`, certificados, `categories`).
- Inserta:
  - `logs` y `phishing`.

---

## 🗄 Modelo de datos (resumen)

- `companies(id, name)`
- `users(id, company_id, username, email, password, role, logged)` → **FK** `company_id → companies.id`
- `logs(id, company_id, status?, type, indicators, severity, date, time, actions_taken)` → **FK** `company_id → companies.id`
- `login(id, log_id, login_timestamp, user_id, round_trip_time, ip_address, country, asn, user_agent, country_code, abuse_confidence_score, last_reported_at, usage_type, domain, total_reports)` → **FK** `log_id → logs.id`
- `ddos(id, log_id, ... métricas ..., Indicadores, Score, Severity, Tipo, Estandar, Description, Ataques/CVEs tipicos, Como proteger, date, time)` → **FK** `log_id → logs.id`
- `phishing(id, logs_id, url, status, malicious, suspicious, undetected, harmless, timeout, whois, tags, dns_records, last_dns_records_date, registrar, expiration_date, tld, issuer, subject_cn, cert_not_before, cert_not_after, cert_key_size, thumbprint_sha256, reputation, popularity_ranks, jarm, categories)` → **FK** `logs_id → logs.id`

> El diagrama completo está incluido en el documento Word generado.

---

## 🔒 Seguridad y buenas prácticas

- Mueve **todas** las claves/URIs a variables de entorno (no hardcodear).
- Valida los JSON en endpoints `POST` (p. ej. Marshmallow/Pydantic).
- Desactiva `DEBUG` en producción.
- Controla CORS a dominios de tu frontend.
- Considera colas (Celery/RQ) en lugar de threads para cargas reales.

---

## 🧷 Solución de problemas

- **`psycopg2` falla al instalar**: usa `psycopg2-binary==2.9.9`.
- **Render plan free**: el thread del logger se detendrá al hibernar.
- **Plotly no renderiza en front**: usa el JSON devuelto con tu componente de charts (p. ej. React-Plotly).