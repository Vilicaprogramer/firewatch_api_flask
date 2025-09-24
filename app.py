from flask import Flask, jsonify
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


@app.route("/grafica_ddos", methods= ["POST"])
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

@app.route("/grafica_phishing", methods= ["POST"])
def graf_phishing():
    # Conexión a la base de datos
    conn = get_connection()

    query = """
    SELECT indicators, COUNT(*) AS cantidad
    FROM logs
    WHERE indicators IN ('Correo seguro', 'Posible phishing')
    GROUP BY indicators;
    """
    df = pd.read_sql(query, conn)
    conn.close()

    # Agrupar
    df_group = df.groupby('indicators')['severity'].size().reset_index(name='total')

    fig_dict = create_pie_chart(df_group, "PHISHING")
    return jsonify(fig_dict)

@app.route("/grafica_login", methods= ["POST"])
def graf_login():
    # Conexión a la base de datos
    conn = get_connection()

    query = """
    SELECT *
    FROM public.logs
    WHERE indicators IN ('Robo de credenciales', 'Cuenta comprometida', 'Ataque fallido', 'Log in válido');
    """
    df = pd.read_sql(query, conn)
    conn.close()

    # Agrupar
    df_group = df.groupby('indicators')['severity'].size().reset_index(name='total')

    fig_dict = create_pie_chart(df_group, "LOGIN")
    return jsonify(fig_dict)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
