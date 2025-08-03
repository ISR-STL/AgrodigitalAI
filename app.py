from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, g, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import io, csv, datetime, requests, os

# --- APP SETUP ---
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY', 'senha-forte-aqui')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///agrodigital.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- RATE LIMITER ---
limiter = Limiter(key_func=get_remote_address, default_limits=["1000 per day", "200 per hour"])
limiter.init_app(app)

# --- MULTILÍNGUE ---
IDIOMAS = ['pt','en','es','de','ru','zh','ar','hi']
def traduzir(textos):
    return textos.get(getattr(g, 'lang', 'pt'), list(textos.values())[0])

@app.before_request
def before_request():
    g.lang = request.cookies.get('lang', 'pt')
    if g.lang not in IDIOMAS:
        g.lang = 'pt'

@app.route('/setlang/<lang>')
def set_lang(lang):
    if lang not in IDIOMAS:
        lang = 'pt'
    resp = make_response(redirect(request.referrer or url_for('painel')))
    resp.set_cookie('lang', lang, max_age=30*24*3600)
    return resp

@app.route('/')
def index():
    return redirect(url_for('login'))

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user')

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Venda(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    investidor = db.Column(db.String(80))
    token = db.Column(db.String(40))
    valor = db.Column(db.Float)
    data = db.Column(db.String(20))
    status = db.Column(db.String(20))
    id_tx = db.Column(db.String(80))

class NFT(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80))
    preco = db.Column(db.Float)
    owner = db.Column(db.String(80))
    status = db.Column(db.String(20), default='disponivel')

# --- LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def registrar_log(user, action):
    log = Log(user=user, action=action)
    db.session.add(log)
    db.session.commit()

def is_admin(): return current_user.is_authenticated and current_user.role == 'admin'
def is_gerente(): return current_user.is_authenticated and current_user.role == 'gerente'
def is_supervisor(): return current_user.is_authenticated and current_user.role == 'supervisor'

# --- (suas rotas: login, painel, usuários, logs, gpt, etc.)

# --- INICIALIZAÇÃO DO BANCO ---
def cria_banco_admin():
    db.create_all()
    add_data = False
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password='admin123', role='admin'))
        add_data = True
    if not User.query.filter_by(username='supervisor').first():
        db.session.add(User(username='supervisor', password='sup123', role='supervisor'))
        add_data = True
    if not Venda.query.first():
        db.session.add(Venda(investidor="Carlos Silva", token="AGD", valor=15000, data="2025-07-30", status="Aprovada", id_tx="0x123..."))
        db.session.add(Venda(investidor="Maria Souza", token="CornToken", valor=27000, data="2025-07-29", status="Pendente", id_tx="0x456..."))
        add_data = True
    if not NFT.query.first():
        db.session.add(NFT(nome='NFT1', preco=0.5, owner='', status='disponivel'))
        db.session.add(NFT(nome='NFT2', preco=1.0, owner='', status='disponivel'))
        add_data = True
    if add_data:
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        cria_banco_admin()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)