from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, g, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import io, csv, datetime, requests, os

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY', 'senha-forte-aqui')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///agrodigital.db'
db = SQLAlchemy(app)

# --- RATE LIMIT - Flask-Limiter 3.x (correto) ---
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour"]
)
limiter.init_app(app)

# --- SUPORTE MULTILÍNGUE ---
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

# --- ROTA PRINCIPAL (ACESSO RAIZ) ---
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

# --- LOGIN ---
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

# --- AUTENTICAÇÃO ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20/minute;100/hour")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            registrar_log(user.username, 'Login realizado')
            return redirect(url_for('painel'))
        else:
            flash(traduzir({
                'pt':'Usuário ou senha inválidos', 'en':'Invalid user or password',
                'es':'Usuario o contraseña inválidos', 'de':'Benutzer oder Passwort ungültig',
                'ru':'Неверное имя пользователя или пароль', 'zh':'用户或密码无效',
                'ar':'اسم المستخدم أو كلمة المرور غير صحيحة', 'hi':'यूज़र या पासवर्ड अमान्य है'
            }))
    return render_template('login.html', lang=g.lang, traduzir=traduzir)

@app.route('/logout')
@login_required
def logout():
    registrar_log(current_user.username, 'Logout realizado')
    logout_user()
    return redirect(url_for('login'))

# --- PAINEL EXECUTIVO ---
@app.route('/painel')
@login_required
@limiter.limit("60/minute")
def painel():
    query = Venda.query
    investidor = request.args.get('investidor')
    token = request.args.get('token')
    status = request.args.get('status')
    data = request.args.get('data')
    if investidor:
        query = query.filter(Venda.investidor.ilike(f'%{investidor}%'))
    if token:
        query = query.filter_by(token=token)
    if status:
        query = query.filter_by(status=status)
    if data:
        query = query.filter_by(data=data)
    vendas = query.order_by(Venda.data.desc()).all()
    total_vendido = sum([v.valor for v in vendas])
    saldo_caixa = total_vendido
    return render_template("painel.html", vendas=vendas, total_vendido=total_vendido, saldo_caixa=saldo_caixa, lang=g.lang, traduzir=traduzir)

# --- CRUD USUÁRIOS ---
@app.route('/usuarios')
@login_required
def usuarios():
    if not is_admin():
        flash(traduzir({'pt':'Acesso restrito', 'en':'Restricted access'}))
        return redirect(url_for('painel'))
    users = User.query.all()
    return render_template('usuarios.html', users=users, lang=g.lang, traduzir=traduzir)

@app.route('/usuarios/novo', methods=['GET', 'POST'])
@login_required
def novo_usuario():
    if not is_admin():
        flash(traduzir({'pt':'Acesso restrito', 'en':'Restricted access'}))
        return redirect(url_for('painel'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        if User.query.filter_by(username=username).first():
            flash(traduzir({'pt':'Usuário já existe', 'en':'User already exists'}))
            return redirect(url_for('usuarios'))
        novo = User(username=username, password=password, role=role)
        db.session.add(novo)
        db.session.commit()
        registrar_log(current_user.username, f'Cadastrou usuário: {username}')
        return redirect(url_for('usuarios'))
    return render_template('cadastro_usuario.html', lang=g.lang, traduzir=traduzir, user=None, editar=False)

@app.route('/usuarios/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    if not is_admin():
        flash(traduzir({'pt':'Acesso restrito', 'en':'Restricted access'}))
        return redirect(url_for('painel'))
    user = User.query.get(user_id)
    if not user:
        flash(traduzir({'pt':'Usuário não encontrado', 'en':'User not found'}))
        return redirect(url_for('usuarios'))
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.password = request.form['password']
        user.role = request.form.get('role', user.role)
        db.session.commit()
        registrar_log(current_user.username, f'Editou usuário: {user.username}')
        return redirect(url_for('usuarios'))
    return render_template('cadastro_usuario.html', lang=g.lang, traduzir=traduzir, user=user, editar=True)

@app.route('/usuarios/delete/<int:user_id>')
@login_required
def deletar_usuario(user_id):
    if not is_admin():
        flash(traduzir({'pt':'Acesso restrito', 'en':'Restricted access'}))
        return redirect(url_for('painel'))
    usuario = User.query.get(user_id)
    if usuario and usuario.username != 'admin':
        registrar_log(current_user.username, f'Removeu usuário: {usuario.username}')
        db.session.delete(usuario)
        db.session.commit()
    else:
        flash(traduzir({'pt':'Não é permitido remover o usuário admin!', 'en':'Cannot remove admin user!'}))
    return redirect(url_for('usuarios'))

# --- LOGS AUDITORIA ---
@app.route('/logs')
@login_required
def logs():
    if not is_admin():
        flash(traduzir({'pt':'Acesso restrito', 'en':'Restricted access'}))
        return redirect(url_for('painel'))
    logs = Log.query.order_by(Log.timestamp.desc()).limit(300).all()
    return render_template('logs.html', logs=logs, lang=g.lang, traduzir=traduzir)

# --- EXPORTAÇÃO CSV & API ---
@app.route('/exportar_csv')
@login_required
def exportar_csv():
    vendas = Venda.query.all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Investidor', 'Token', 'Valor', 'Data', 'Status', 'ID Tx'])
    for v in vendas:
        cw.writerow([v.investidor, v.token, v.valor, v.data, v.status, v.id_tx])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    registrar_log(current_user.username, 'Exportou CSV de vendas')
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='vendas.csv')

@app.route('/api/vendas')
@login_required
def api_vendas():
    vendas = Venda.query.all()
    return jsonify([
        {'investidor': v.investidor, 'token': v.token, 'valor': v.valor, 'data': v.data,
         'status': v.status, 'id_tx': v.id_tx} for v in vendas
    ])

# --- MARKETPLACE NFT/TOKEN ---
@app.route('/marketplace')
@login_required
def marketplace():
    nfts = NFT.query.filter_by(status='disponivel').all()
    return render_template('marketplace.html', nfts=nfts, lang=g.lang, traduzir=traduzir)

@app.route('/nft/comprar/<int:nft_id>')
@login_required
def comprar_nft(nft_id):
    nft = NFT.query.get(nft_id)
    if nft and nft.status == 'disponivel':
        nft.owner = current_user.username
        nft.status = 'vendido'
        db.session.commit()
        registrar_log(current_user.username, f'Comprou NFT: {nft.nome}')
        flash(traduzir({'pt':'NFT comprado com sucesso!', 'en':'NFT successfully purchased!'}))
    else:
        flash(traduzir({'pt':'NFT não disponível.', 'en':'NFT not available.'}))
    return redirect(url_for('marketplace'))

# --- DASHBOARD BI ---
@app.route('/bi')
@login_required
def bi():
    return render_template('bi.html', lang=g.lang, traduzir=traduzir)

# --- GPT ---
@app.route('/gpt', methods=['GET', 'POST'])
@login_required
def gpt():
    resposta = None
    pergunta = ''
    if request.method == 'POST':
        pergunta = request.form['pergunta']
        api_key = os.getenv('OPENAI_API_KEY', 'SUA_KEY_AQUI')
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        body = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Você é um assistente especializado em negócios e vendas."},
                {"role": "user", "content": pergunta}
            ]
        }
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=20)
            rj = resp.json()
            resposta = rj.get('choices', [{}])[0].get('message', {}).get('content', 'Erro ao processar resposta')
        except Exception as e:
            resposta = f"Erro GPT: {e}"
        registrar_log(current_user.username, f'Usou GPT: {pergunta}')
    return render_template('gpt.html', lang=g.lang, traduzir=traduzir, resposta=resposta, pergunta=pergunta)

# --- BACKUP ---
@app.route('/backup')
@login_required
def backup():
    registrar_log(current_user.username, 'Download do backup')
    return send_file('agrodigital.db', as_attachment=True)

# --- GOVERNANÇA ---
@app.route('/governanca')
@login_required
def governanca():
    flash(traduzir({'pt':'Módulo de governança em desenvolvimento.', 'en':'Governance module in development.'}))
    return redirect(url_for('painel'))

# --- SEGURANÇA ---
@app.after_request
def set_secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdn.plot.ly"
    return response

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
    app.run(debug=True)