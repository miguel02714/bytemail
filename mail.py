from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

# =========================
# Configuração do Flask
# =========================
app = Flask(__name__)
app.secret_key = "chave-super-secreta"

# Configurações do cookie para permitir iframe
app.config.update(
    SESSION_COOKIE_SAMESITE="None",  # permite uso em iframe cross-site
    SESSION_COOKIE_SECURE=False       # True se estiver usando HTTPS
)

# Banco de dados
DB = "bytemail.db"

# =========================
# Auxiliares
# =========================
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT DEFAULT 'Usuário',
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

# =========================
# Rotas
# =========================
@app.route("/")
def root():
    if "user" in session:
        return redirect(url_for("inicio"))
    return redirect(url_for("login"))

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
            flash("Cadastro realizado com sucesso!", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("E-mail já cadastrado!", "error")
            return render_template("registro.html")

    return render_template("registro.html")

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
            session["user"] = user["email"]
            flash(f"Bem-vindo {user['nome']}!", "success")
            return redirect(url_for("inicio"))
        else:
            flash("Credenciais inválidas!", "error")
            return render_template("login.html")

    return render_template("login.html")

# -------------------------
# Logout
# -------------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logout realizado!", "success")
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

# =========================
# Inicialização
# =========================
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
