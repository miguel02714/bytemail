from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = "chave-super-secreta"

DB = "bytemail.db"
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------------
# Funções auxiliares
# -------------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------
# Inicialização do banco
# -------------------------
def init_db():
    conn = get_db()
    c = conn.cursor()
    # Usuários
    c.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT DEFAULT 'Usuário',
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL,
        foto TEXT DEFAULT 'https://i.pravatar.cc/200',
        status TEXT DEFAULT 'ativo'
    )
    """)
    # Emails
    c.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        remetente TEXT NOT NULL,
        destinatario TEXT NOT NULL,
        assunto TEXT,
        mensagem TEXT,
        hora TEXT
    )
    """)
    conn.commit()
    conn.close()

# -------------------------
# Rotas principais
# -------------------------
@app.route("/")
def root():
    if "user" in session:
        return redirect(url_for("inicio"))
    return redirect(url_for("login"))

# -------------------------
# Login
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM usuarios WHERE LOWER(email)=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["senha"], senha):
            session["user"] = email
            return redirect(url_for("inicio"))
        else:
            return render_template("login.html", erro="Credenciais inválidas")
    return render_template("login.html")

# -------------------------
# Registro
# -------------------------
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nome = request.form.get("nome", "Usuário")
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]
        hashed_senha = generate_password_hash(senha)

        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)",
                      (nome, email, hashed_senha))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("registro.html", erro="E-mail já registrado")
    return render_template("registro.html")

# -------------------------
# Logout
# -------------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# -------------------------
# Página inicial
# -------------------------
@app.route("/index")
def inicio():
    if "user" not in session:
        return redirect(url_for("login"))

    user_email = session["user"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE LOWER(email)=?", (user_email,))
    user = c.fetchone()
    conn.close()
    return render_template("index.html", user=user)

# -------------------------
# Perfil
# -------------------------
@app.route("/perfil", methods=["GET"])
def perfil():
    if "user" not in session:
        return redirect(url_for("login"))

    user_email = session["user"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE LOWER(email)=?", (user_email,))
    user = c.fetchone()
    conn.close()
    return render_template("perfil.html", user=user)

@app.route("/perfil/editar", methods=["POST"])
def editar_perfil():
    if "user" not in session:
        return redirect(url_for("login"))

    user_email = session["user"]
    nome = request.form.get("nome", "").strip()
    status = request.form.get("status", "ativo")
    foto = request.files.get("foto")

    conn = get_db()
    c = conn.cursor()

    foto_path = None
    if foto and allowed_file(foto.filename):
        filename = secure_filename(f"{user_email.replace('@','_')}_{foto.filename}")
        caminho = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        foto.save(caminho)
        foto_path = f"/{UPLOAD_FOLDER}/{filename}"

    if foto_path:
        c.execute("UPDATE usuarios SET nome=?, status=?, foto=? WHERE LOWER(email)=?", 
                  (nome, status, foto_path, user_email.lower()))
    else:
        c.execute("UPDATE usuarios SET nome=?, status=? WHERE LOWER(email)=?", 
                  (nome, status, user_email.lower()))

    conn.commit()
    conn.close()

    return redirect(url_for("perfil"))

# -------------------------
# API Emails
# -------------------------
@app.route("/api/emails")
def api_emails():
    if "user" not in session:
        return jsonify([])

    user = session["user"].strip().lower()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM emails WHERE LOWER(destinatario)=? ORDER BY id DESC", (user,))
    emails = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(emails)

@app.route("/api/email/<int:id>")
def api_email(id):
    if "user" not in session:
        return jsonify({"error": "não autenticado"}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM emails WHERE id=?", (id,))
    email = c.fetchone()
    conn.close()

    if email:
        return jsonify(dict(email))
    return jsonify({"error": "email não encontrado"}), 404

# -------------------------
# Enviar email
# -------------------------
@app.route("/enviar", methods=["POST"])
def enviar():
    if "user" not in session:
        return jsonify({"status": "error", "message": "não autenticado"}), 403

    remetente = session["user"].strip().lower()
    destinatario = request.form["para"].strip().lower()
    assunto = request.form.get("assunto", "")
    mensagem = request.form.get("mensagem", "")
    hora = datetime.now().strftime("%H:%M")

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO emails (remetente, destinatario, assunto, mensagem, hora) VALUES (?, ?, ?, ?, ?)",
              (remetente, destinatario, assunto, mensagem, hora))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "E-mail enviado com sucesso!"})

# -------------------------
# Inicialização
# -------------------------
if __name__ == "__main__":
    init_db()
    # Rodar no localhost sem HTTPS, funciona em iframe
    app.run(host="0.0.0.0", port=5000, debug=True)
