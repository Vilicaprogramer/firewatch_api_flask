from flask import Flask, jsonify, request, send_file
import plotly.express as px
import plotly.io as pio
from flask_cors import CORS
import psycopg2
import pandas as pd
import seaborn as sns
import json
import os

app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)
#CORS(app, origins=["http://localhost:5173"])

def get_connection():
    # Conexión a la base de datos
    return psycopg2.connect(
        dbname=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        host=os.environ.get("DB_HOST"),
        port=os.environ.get("DB_PORT")
    )


def create_pie_chart(df_group, title):
    colors = [f"rgb({int(r*255)}, {int(g*255)}, {int(b*255)})"
              for r, g, b in sns.color_palette("pastel", len(df_group))]
    fig = px.pie(
        df_group,
        values="total",
        names="indicators",
        title=title,
        color="indicators",
        color_discrete_sequence=colors,
        hole=0.7
    )
    return json.loads(pio.to_json(fig))

#==================   END POINT ATAQUES EN DIRECTO   =========================
import threading
import time
import random
from limpieza_datos import clean_data_ddos, tres_en_uno

# Control global
is_logging = False

def malware_type_detection(record):
    if 'Destination Port' in record.keys():
        clean_data_ddos(record)
    else:
        tres_en_uno(record)
    #elif:
        #clean_data_phishing(dict)

def background_logger():
    global is_logging
    is_logging = True

    # cargar datasets una vez
    df_int_login = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df1_alimentacion_login.csv")
    df_ddos = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df_alimentacion_DDOS.csv")
    #df_phishing = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df_prueba_phising.csv")

    login_list = (
        df_int_login.to_dict(orient="records")
        + df_ddos.to_dict(orient="records")
    )

    while is_logging:  # bucle infinito hasta que paremos
        record = random.choice(login_list)   # elige un registro al azar
        try:
            malware_type_detection(record)
        except Exception as e:
            app.logger.error(f"Error procesando log: {e}")

        time.sleep(30)

    app.logger.info("background_logger detenido")

@app.route("/start-logging", methods=["POST"])
def start_logging():
    """Se llama desde React al hacer login."""
    global is_logging
    if not is_logging:
        thread = threading.Thread(target=background_logger, daemon=True)
        thread.start()
        return jsonify({"status": "logging started"}), 200
    else:
        return jsonify({"status": "already running"}), 400

@app.route("/stop-logging", methods=["POST"])
def stop_logging():
    """Se llama desde React al hacer logout."""
    global is_logging
    is_logging = False
    return jsonify({"status": "logging stopped"}), 200



#==================   END POINT DE GRÁFICAS   =========================
@app.route("/grafica_ddos", methods= ["GET"])
def graf_ddos():
    # Conexión a la base de datos
    conn = get_connection()

    query = """
    SELECT *
    FROM public.logs
    WHERE indicators IN ('BENIGN', 'XSS', 'Brute Force', 'Sql Injection');
    """
    df = pd.read_sql(query, conn)
    conn.close()

    # Agrupar
    df_group = df.groupby('indicators')['severity'].size().reset_index(name='total')

    fig_dict = create_pie_chart(df_group, "DDOS")
    return jsonify(fig_dict)

@app.route("/grafica_phishing", methods= ["GET"])
def graf_phishing():
    # Conexión a la base de datos
    conn = get_connection()

    query = """
    SELECT * FROM logs
    WHERE indicators IN ('Correo seguro', 'Posible phishing')
    """
    df = pd.read_sql(query, conn)
    conn.close()

    # Agrupar
    df_group = df.groupby('indicators')['severity'].size().reset_index(name='total')

    fig_dict = create_pie_chart(df_group, "PHISHING")
    return jsonify(fig_dict)

@app.route("/grafica_login", methods= ["GET"])
def graf_login():
    # Conexión a la base de datos
    conn = get_connection()

    query = """
    SELECT *
    FROM public.logs
    WHERE indicators IN ('Robo de credenciales', 'Cuenta comprometida', 'Ataque fallido', 'Login válido');
    """
    df = pd.read_sql(query, conn)
    conn.close()

    # Agrupar
    df_group = df.groupby('indicators')['severity'].size().reset_index(name='total')

    fig_dict = create_pie_chart(df_group, "LOGIN")
    return jsonify(fig_dict)


#==================   END POINT DE PDFs   =========================
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.platypus.flowables import HRFlowable

@app.route("/download_pdf_phishing", methods=["POST"])
def download_pdf_phishing():
    data = request.get_json()

    logs_id = data.get("logs_id", "Sin información adicional")
    url = data.get("url", "Sin información adicional")
    status = data.get("status", "Sin información adicional")
    malicious = data.get("malicious", "Sin información adicional")
    suspicious = data.get("suspicious", "Sin información adicional")
    undetected = data.get("undetected", "Sin información adicional")
    harmless = data.get("harmless", "Sin información adicional")
    timeout = data.get("timeout", "Sin información adicional")
    whois = data.get("whois", "Sin información adicional")
    tags = data.get("tags", "Sin información adicional")
    dns_records = data.get("dns_records", "Sin información adicional")
    last_dns_records_date = data.get("last_dns_records_date", "Sin información adicional")
    registrar = data.get("registrar", "Sin información adicional")
    expiration_date = data.get("expiration_date", "Sin información adicional")
    tld = data.get("tld", "Sin información adicional")
    issuer = data.get("issuer", "Sin información adicional")
    subject_CN = data.get("subject_CN", "Sin información adicional")
    cert_not_before = data.get("cert_not_before", "Sin información adicional")
    cert_not_after = data.get("cert_not_after", "Sin información adicional")
    cert_key_size = data.get("cert_key_size", "Sin información adicional")
    thumbprint_sha256 = data.get("thumbprint_sha256", "Sin información adicional")
    reputation = data.get("reputation", "Sin información adicional")
    popularity_ranks = data.get("popularity_ranks", "Sin información adicional")
    jarm = data.get("jarm", "Sin información adicional")
    categories = data.get("categories", "Sin información adicional")


    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story_elements = []
    story_elements.append(Paragraph("INFORME DE ANÁLISIS DE URL", styles["Heading2"]))
    story_elements.append(HRFlowable(width="100%", thickness=1))
    story_elements.append(Spacer(1, 24))

    story_elements.append(Paragraph(f"<b>Logs id:</b> {logs_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Url:</b> {url}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Status:</b> {status}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Malicious:</b> {malicious}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Suspicious:</b> {suspicious}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Undetected:</b> {undetected}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Harmless:</b> {harmless}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Timeout:</b> {timeout}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Whois:</b> {whois}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Tags:</b> {tags}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Dns Records:</b> {dns_records}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Last dns records_date:</b> {last_dns_records_date}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Registrar:</b> {registrar}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Expiration_date:</b> {expiration_date}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>TLD:</b> {tld}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Issuer:</b> {issuer}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Subject CN:</b> {subject_CN}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Cert not Before:</b> {cert_not_before}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Cert not After:</b> {cert_not_after}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Cert Key Size:</b> {cert_key_size}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Thumbprint Sha256:</b> {thumbprint_sha256}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Reputation:</b> {reputation}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Popularity Ranks:</b> {popularity_ranks}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Jarm:</b> {jarm}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Categories:</b> {categories}", styles["Normal"]))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Informe_{logs_id.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )

@app.route("/download_pdf_login", methods=["POST"])
def download_pdf_login():
    data = request.get_json()

    log_id = data.get("log_id", "Sin información adicional")
    login_timestamp = data.get("login_timestamp", "Sin información adicional")
    user_id = data.get("user_id", "Sin información adicional")
    round_trip_time = data.get("round_trip_time", "Sin información adicional")
    ip_address = data.get("ip_address", "Sin información adicional")
    country = data.get("country", "Sin información adicional")
    asn = data.get("asn", "Sin información adicional")
    user_agent = data.get("user_agent", "Sin información adicional")
    country_code = data.get("country_code", "Sin información adicional")
    abuse_confidence_score = data.get("abuse_confidence_score", "Sin información adicional")
    last_reported_at = data.get("last_reported_at", "Sin información adicional")
    usage_type = data.get("usage_type", "Sin información adicional")
    domain = data.get("domain", "Sin información adicional")
    total_reports = data.get("total_reports", "Sin información adicional")

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story_elements = []
    story_elements.append(Paragraph("INFORME DE LOGIN", styles["Heading2"]))
    story_elements.append(HRFlowable(width="100%", thickness=1))
    story_elements.append(Spacer(1, 24))

    story_elements.append(Paragraph(f"<b>Log_id:</b> {log_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Login_timestamp:</b> {login_timestamp}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>User Id:</b> {user_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Round Trip Time:</b> {round_trip_time}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>IP Address:</b> {ip_address}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Country:</b> {country}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>ASN:</b> {asn}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>User Agent:</b> {user_agent}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Country Code:</b> {country_code}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Abuse Confidence Score:</b> {abuse_confidence_score}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Last Reported At:</b> {last_reported_at}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Usage Type:</b> {usage_type}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Domain:</b> {domain}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Total Reports:</b> {total_reports}", styles["Normal"]))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Informe_{log_id.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )

@app.route("/download_pdf_ddos", methods=["POST"])
def download_pdf_ddos():
    data = request.get_json()

    # Extraer todos los campos
    log_id = data.get("Logs id", "Sin información adicional")
    destination_port = data.get("Destination Port", "Sin información adicional")
    flow_duration = data.get("Flow Duration", "Sin información adicional")
    total_fwd_packets = data.get("Total Fwd Packets", "Sin información adicional")
    total_backward_packets = data.get("Total Backward Packets", "Sin información adicional")
    flow_bytes_s = data.get("Flow Bytes/s", "Sin información adicional")
    flow_packets_s = data.get("Flow Packets/s", "Sin información adicional")
    fwd_packet_length_mean = data.get("Fwd Packet Length Mean", "Sin información adicional")
    fwd_packet_length_std = data.get("Fwd Packet Length Std", "Sin información adicional")
    min_packet_length = data.get("Min Packet Length", "Sin información adicional")
    max_packet_lengths = data.get("Max Packet Lengths", "Sin información adicional")
    flow_iat_mean = data.get("Flow IAT Mean", "Sin información adicional")
    flow_iat_std = data.get("Flow IAT Std", "Sin información adicional")
    syn_flag_count = data.get("SYN Flag Count", "Sin información adicional")
    ack_flag_count = data.get("ACK Flag Count", "Sin información adicional")
    down_up_ratio = data.get("Down/Up Ratio", "Sin información adicional")
    active_mean = data.get("Active Mean", "Sin información adicional")
    idle_mean = data.get("Idle Mean", "Sin información adicional")
    indicadores = data.get("Indicadores", "Sin información adicional")
    score = data.get("Score", "Sin información adicional")
    severity = data.get("Severity", "Sin información adicional")
    tipo = data.get("Tipo", "Sin información adicional")
    estandar = data.get("Estandar", "Sin información adicional")
    description = data.get("Description", "Sin información adicional")
    ataques_cves_tipicos = data.get("Ataques/CVEs tipicos", "Sin información adicional")
    como_proteger = data.get("Como proteger", "Sin información adicional")
    date = data.get("Date", "Sin información adicional")
    time = data.get("Time", "Sin información adicional")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story_elements = []

    # Título y línea horizontal
    story_elements.append(Paragraph("INFORME DE ANÁLISIS DE FLUJO", styles["Heading2"]))
    story_elements.append(HRFlowable(width="100%", thickness=1))
    story_elements.append(Spacer(1, 24))

    # Cada campo en su propia línea
    story_elements.append(Paragraph(f"<b>Logs id:</b> {log_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Destination Port:</b> {destination_port}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow Duration:</b> {flow_duration}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Total Fwd Packets:</b> {total_fwd_packets}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Total Backward Packets:</b> {total_backward_packets}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow Bytes/s:</b> {flow_bytes_s}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow Packets/s:</b> {flow_packets_s}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Fwd Packet Length Mean:</b> {fwd_packet_length_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Fwd Packet Length Std:</b> {fwd_packet_length_std}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Min Packet Length:</b> {min_packet_length}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Max Packet Lengths:</b> {max_packet_lengths}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow IAT Mean:</b> {flow_iat_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow IAT Std:</b> {flow_iat_std}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>SYN Flag Count:</b> {syn_flag_count}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>ACK Flag Count:</b> {ack_flag_count}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Down/Up Ratio:</b> {down_up_ratio}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Active Mean:</b> {active_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Idle Mean:</b> {idle_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Indicadores:</b> {indicadores}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Score:</b> {score}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Severity:</b> {severity}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Tipo:</b> {tipo}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Estandar:</b> {estandar}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Description:</b> {description}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Ataques/CVEs tipicos:</b> {ataques_cves_tipicos}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Como proteger:</b> {como_proteger}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Date:</b> {date}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Time:</b> {time}", styles["Normal"]))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Informe_{log_id.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
