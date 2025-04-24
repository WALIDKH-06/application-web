from flask import Flask, request, render_template, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime, timedelta
import random
import string
from flask_mail import Mail, Message
from numpy import log as Ln, exp as e
import re
import os 
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'NUNUNUNU'

app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'default_email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'default_password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'default_email@gmail.com')

db = SQLAlchemy(app)
mail = Mail(app)

login_attempts = {}
password_reset_tokens = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/index')
def index():
    return render_template('index.html')

def validate_password_complexity(password):
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères."
    
    if not re.search(r'\d', password):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    
    if not re.search(r'[a-z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule."
    
    if not re.search(r'[A-Z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial."
    
    return True, "Mot de passe valide."

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Cet email est déjà utilisé. Veuillez en choisir un autre.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas. Veuillez réessayer.', 'danger')
            return render_template('register.html')
        
        is_valid, message = validate_password_complexity(password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html')
        
        new_user = User(username=username, email=email, password=password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Votre compte a été créé avec succès! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Une erreur est survenue lors de l\'inscription: {str(e)}', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        ip_address = request.remote_addr
        
        if ip_address in login_attempts and login_attempts[ip_address]['attempts'] >= 5:
            last_attempt = login_attempts[ip_address]['last_attempt']
            if datetime.now() < last_attempt + timedelta(minutes=5):
                remaining_time = int((last_attempt + timedelta(minutes=5) - datetime.now()).total_seconds() / 60)
                flash(f"Trop de tentatives. Réessayez dans {remaining_time:.0f} minutes", "danger")
                return redirect(url_for('login'))
            else:
                login_attempts.pop(ip_address)
        
        user = User.query.filter_by(email=email).first()
        password = request.form['password']
        
        if user and user.check_password(password):
            if ip_address in login_attempts:
                login_attempts.pop(ip_address)
            session['user_id'] = user.id
            flash("Connexion réussie", "success")
            return redirect(url_for('dashboard'))
        
        if ip_address not in login_attempts:
            login_attempts[ip_address] = {'attempts': 0, 'last_attempt': datetime.now()}
        
        login_attempts[ip_address]['attempts'] += 1
        login_attempts[ip_address]['last_attempt'] = datetime.now()
        
        remaining_attempts = 5 - login_attempts[ip_address]['attempts']
        if remaining_attempts > 0:
            flash(f"Identifiants incorrects. Il reste {remaining_attempts} tentative(s)", "danger")
        else:
            flash("Trop de tentatives. Veuillez réessayer plus tard", "danger")
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            password_reset_tokens[token] = {
                'user_id': user.id,
                'expires': datetime.now() + timedelta(hours=1)
            }
            
            try:
                msg = Message(
                    'Réinitialisation de mot de passe',
                    recipients=[user.email],
                    body=f'''Pour réinitialiser votre mot de passe, cliquez sur le lien :
{url_for('reset_password', token=token, _external=True)}

Ce lien expirera dans 1 heure.
'''
                )
                mail.send(msg)
                flash("Email de réinitialisation envoyé à votre adresse email", "info")
            except Exception as e:
                app.logger.error(f"Erreur email: {str(e)}")
                flash("Erreur d'envoi d'email", "danger")
        else:
            flash("Aucun compte associé à cette adresse email", "danger")
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_data = password_reset_tokens.get(token)
    
    if not token_data or token_data['expires'] < datetime.now():
        flash("Lien invalide ou expiré", "danger")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        user = User.query.get(token_data['user_id'])
        new_password = request.form['password']
        
        is_valid, message = validate_password_complexity(new_password)
        if not is_valid:
            flash(message, "danger")
            return render_template('reset_password.html', token=token)
            
        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.commit()
        password_reset_tokens.pop(token)
        flash("Mot de passe réinitialisé avec succès", "success")
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Veuillez vous connecter", "warning")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    result = None
    error = None
    
    if request.method == 'POST':
        try:
            Xa = float(request.form["Xa"])
            T = float(request.form["T"])
            result = calcul_diffusion(Xa, T)
        except ValueError as ve:
            error = str(ve)
        except Exception as e:
            error = f"Erreur de calcul : {str(e)}"
    
    return render_template('dashboard.html', user=user, result=result, error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Déconnexion réussie", "info")
    return redirect(url_for('index'))


@app.route('/about')
def about():
    return render_template('info.html')

CONSTANTS = {
    'V_exp': 1.33e-05,
    'aBA': 194.5302,
    'aAB': -10.7575,
    'lambda_A': 1.127,
    'lambda_B': 0.973,
    'qA': 1.432,
    'qB': 1.4,
    'D_AB': 2.1e-5,
    'D_BA': 2.67e-5
}

def calcul_diffusion(Xa, T):
    if not (0 <= Xa <= 1):
        raise ValueError("La fraction Xa doit être entre 0 et 1")
    if T <= 0:
        raise ValueError("La température doit être positive")

    Xb = 1 - Xa
    phiA = (Xa * CONSTANTS['lambda_A']) / (Xa * CONSTANTS['lambda_A'] + Xb * CONSTANTS['lambda_B'])
    phiB = 1 - phiA
    tauxAB = e(-CONSTANTS['aAB'] / T)
    tauxBA = e(-CONSTANTS['aBA'] / T)
    tetaA = (Xa * CONSTANTS['qA']) / (Xa * CONSTANTS['qA'] + Xb * CONSTANTS['qB'])
    tetaB = 1 - tetaA
    tetaAA = tetaA / (tetaA + tetaB * tauxBA)
    tetaBB = tetaB / (tetaB + tetaA * tauxAB)
    tetaAB = (tetaA * tauxAB) / (tetaA * tauxAB + tetaB)
    tetaBA = (tetaB * tauxBA) / (tetaB * tauxBA + tetaA)

    termes = (
        Xb * Ln(CONSTANTS['D_AB']) +
        Xa * Ln(CONSTANTS['D_BA']) +
        2 * (Xa * Ln(Xa / phiA) + Xb * Ln(Xb / phiB)) +
        2 * Xb * Xa * (
            (phiA / Xa) * (1 - CONSTANTS['lambda_A'] / CONSTANTS['lambda_B']) +
            (phiB / Xb) * (1 - CONSTANTS['lambda_B'] / CONSTANTS['lambda_A'])
        ) +
        Xb * CONSTANTS['qA'] * (
            (1 - tetaBA ** 2) * Ln(tauxBA) +
            (1 - tetaBB ** 2) * tauxAB * Ln(tauxAB)
        ) +
        Xa * CONSTANTS['qB'] * (
            (1 - tetaAB ** 2) * Ln(tauxAB) +
            (1 - tetaAA ** 2) * tauxBA * Ln(tauxBA)
        )
    )
    solution = e(termes)
    erreur = (abs(solution - CONSTANTS['V_exp']) / CONSTANTS['V_exp']) * 100
    return {
        'lnDab': termes,
        'Dab': solution,
        'erreur': erreur,
        'Xa': Xa,
        'T': T
    }

@app.route('/calcul', methods=["GET","POST"])
def calcul():
    if 'user_id' not in session:
        flash("Veuillez vous connecter", "warning")
        return redirect(url_for('login'))
    if request.method=="POST":
        try:
            Xa = float(request.form["Xa"])
            T = float(request.form["T"])
            data = calcul_diffusion(Xa, T)
            return redirect(url_for('resultat', Xa=Xa, T=T, Dab=data['Dab'], erreur=data['erreur'], lnDab=data['lnDab']))
        except ValueError as ve:
            return render_template("calcul.html", error=str(ve))
        except Exception as e:
            return render_template("calcul.html", error=f"Erreur de calcul : {str(e)}")
    return render_template("calcul.html")

@app.route("/resultat")
def resultat():
    if 'user_id' not in session:
        flash("Veuillez vous connecter", "warning")
        return redirect(url_for('login'))
    Xa = float(request.args.get('Xa'))
    T = float(request.args.get('T'))
    Dab = float(request.args.get('Dab'))
    erreur = float(request.args.get('erreur'))
    lnDab = float(request.args.get('lnDab'))
    
    return render_template("resultat.html", Xa=Xa, T=T, Dab=Dab, erreur=erreur, lnDab=lnDab)

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)