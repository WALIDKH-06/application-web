from flask import Flask, request, render_template, redirect, session, url_for, flash  # Importation des modules Flask nécessaires pour le fonctionnement de l'application web
from flask_sqlalchemy import SQLAlchemy  # Importation de SQLAlchemy pour la gestion de la base de données
import bcrypt  # Importation de bcrypt pour le hachage sécurisé des mots de passe
from datetime import datetime, timedelta  # Importation des outils de gestion de date et temps
import random  # Importation du module random pour la génération aléatoire
import string  # Importation du module string pour manipuler des chaînes de caractères
from flask_mail import Mail, Message  # Importation des modules pour l'envoi d'emails
from numpy import log as Ln, exp as e
import re


app = Flask(__name__)  # Création de l'instance de l'application Flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Configuration de l'URI de la base de données SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Désactivation du suivi des modifications pour améliorer les performances
app.secret_key = 'NUNUNUNU'  # Définition d'une clé secrète pour sécuriser les sessions (à modifier en production)

# Configuration Mail (mode développement - désactive l'envoi réel)
app.config['MAIL_SUPPRESS_SEND'] = False  # Empêche l'envoi réel d'emails en mode développement
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Configuration du serveur SMTP pour l'envoi d'emails
app.config['MAIL_PORT'] = 587  # Configuration du port pour le serveur SMTP
app.config['MAIL_USE_TLS'] = True  # Activation du chiffrement TLS pour les emails
app.config['MAIL_USERNAME'] = 'walidekhaoudi@gmail.com'  # Nom d'utilisateur pour l'authentification SMTP
app.config['MAIL_PASSWORD'] = 'ybxm vszq saap ajql'  # Mot de passe pour l'authentification SMTP
app.config['MAIL_DEFAULT_SENDER'] = 'walidekhaoudi@gmail.com'  # Adresse email par défaut pour l'expéditeur

# Pour activer l'envoi réel, mettez MAIL_SUPPRESS_SEND = False et configurez les bons paramètres SMTP

db = SQLAlchemy(app)  # Initialisation de l'objet SQLAlchemy avec notre application
mail = Mail(app)  # Initialisation de l'objet Mail avec notre application

# Stockage des tentatives et tokens
login_attempts = {}  # Dictionnaire pour stocker les tentatives de connexion par adresse IP
password_reset_tokens = {}  # Dictionnaire pour stocker les tokens de réinitialisation de mot de passe

class User(db.Model):  # Définition du modèle User pour la base de données
    id = db.Column(db.Integer, primary_key=True)  # Colonne ID comme clé primaire
    username = db.Column(db.String(100), nullable=False)  # Colonne pour le nom d'utilisateur (obligatoire)
    email = db.Column(db.String(100), unique=True, nullable=False)  # Colonne pour l'email (unique et obligatoire)
    password = db.Column(db.String(100), nullable=False)  # Colonne pour le mot de passe haché (obligatoire)
    
    def __init__(self, username, email, password):  # Méthode d'initialisation pour créer un nouvel utilisateur
        self.username = username  # Assignation du nom d'utilisateur
        self.email = email  # Assignation de l'email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # Hachage et assignation du mot de passe

    def check_password(self, password):  # Méthode pour vérifier si le mot de passe est correct
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))  # Vérification du mot de passe en le comparant au hash stocké

# Initialisation DB
with app.app_context():  # Création d'un contexte d'application pour les opérations de base de données
    db.create_all()  # Création des tables dans la base de données si elles n'existent pas

# Routes
@app.route('/index')  # Route pour la page d'accueil
def index():  # Fonction pour gérer la page d'accueil
    return render_template('index.html')  # Rendu du template index.html

# Fonction pour valider la complexité du mot de passe
def validate_password_complexity(password):
    # Vérifier si le mot de passe a au moins 8 caractères
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères."
    
    # Vérifier si le mot de passe contient au moins un chiffre
    if not re.search(r'\d', password):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    
    # Vérifier si le mot de passe contient au moins une lettre minuscule
    if not re.search(r'[a-z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule."
    
    # Vérifier si le mot de passe contient au moins une lettre majuscule
    if not re.search(r'[A-Z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."
    
    # Vérifier si le mot de passe contient au moins un caractère spécial
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
        
        # Vérifier si l'utilisateur existe déjà
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Cet email est déjà utilisé. Veuillez en choisir un autre.', 'danger')
            return render_template('register.html')
        
        # Vérifier si les deux mots de passe sont identiques
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas. Veuillez réessayer.', 'danger')
            return render_template('register.html')
        
        # Vérifier la complexité du mot de passe
        is_valid, message = validate_password_complexity(password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html')
        
        # Création du nouvel utilisateur
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

@app.route('/login', methods=['GET', 'POST'])  # Route pour la connexion avec support des méthodes GET et POST
def login():  # Fonction pour gérer la connexion
    if request.method == 'POST':  # Vérification si la requête est de type POST (soumission du formulaire)
        email = request.form['email']  # Récupération de l'email depuis le formulaire
        ip_address = request.remote_addr  # Récupération de l'adresse IP du client
        
        # Vérification blocage
        if ip_address in login_attempts and login_attempts[ip_address]['attempts'] >= 5:  # Si l'IP a déjà fait 5 tentatives ou plus
            last_attempt = login_attempts[ip_address]['last_attempt']  # Récupération de l'horodatage de la dernière tentative
            if datetime.now() < last_attempt + timedelta(minutes=5):  # Si moins de 5 minutes se sont écoulées depuis la dernière tentative
                remaining_time = int((last_attempt + timedelta(minutes=5) - datetime.now()).total_seconds() / 60)  # Calcul du temps restant en minutes
                flash(f"Trop de tentatives. Réessayez dans {remaining_time:.0f} minutes", "danger")  # Affichage d'un message d'erreur avec le temps restant
                return redirect(url_for('login'))  # Redirection vers la page de connexion
            else:  # Si plus de 5 minutes se sont écoulées
                login_attempts.pop(ip_address)  # Suppression de l'entrée pour cette IP dans le dictionnaire des tentatives
        
        user = User.query.filter_by(email=email).first()  # Recherche de l'utilisateur par email
        password = request.form['password']  # Récupération du mot de passe depuis le formulaire
        
        if user and user.check_password(password):  # Si l'utilisateur existe et le mot de passe est correct
            if ip_address in login_attempts:  # Si l'IP est dans le dictionnaire des tentatives
                login_attempts.pop(ip_address)  # Suppression de l'entrée pour cette IP
            session['user_id'] = user.id  # Stockage de l'ID utilisateur dans la session
            flash("Connexion réussie", "success")  # Affichage d'un message de succès
            return redirect(url_for('dashboard'))  # Redirection vers le tableau de bord
        
        # Gestion tentatives
        if ip_address not in login_attempts:  # Si c'est la première tentative pour cette IP
            login_attempts[ip_address] = {'attempts': 0, 'last_attempt': datetime.now()}  # Initialisation des données de tentative
        
        login_attempts[ip_address]['attempts'] += 1  # Incrémentation du compteur de tentatives
        login_attempts[ip_address]['last_attempt'] = datetime.now()  # Mise à jour de l'horodatage de la dernière tentative
        
        remaining_attempts = 5 - login_attempts[ip_address]['attempts']  # Calcul du nombre de tentatives restantes
        if remaining_attempts > 0:  # S'il reste des tentatives
            flash(f"Identifiants incorrects. Il reste {remaining_attempts} tentative(s)", "danger")  # Affichage du nombre de tentatives restantes
        else:  # Si plus de tentatives disponibles
            flash("Trop de tentatives. Veuillez réessayer plus tard", "danger")  # Message indiquant que l'utilisateur est bloqué
        
        return redirect(url_for('login'))  # Redirection vers la page de connexion
    
    return render_template('login.html')  # Rendu du template login.html pour afficher le formulaire

@app.route('/forgot-password', methods=['GET', 'POST'])  # Route pour la récupération de mot de passe oublié
def forgot_password():  # Fonction pour gérer la récupération de mot de passe
    if request.method == 'POST':  # Vérification si la requête est de type POST (soumission du formulaire)
        email = request.form['email']  # Récupération de l'email depuis le formulaire
        user = User.query.filter_by(email=email).first()  # Recherche de l'utilisateur par email
        
        if user:  # Si l'utilisateur existe
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))  # Génération d'un token aléatoire
            password_reset_tokens[token] = {  # Stockage des informations liées au token
                'user_id': user.id,  # ID de l'utilisateur concerné
                'expires': datetime.now() + timedelta(hours=1)  # Date d'expiration du token (1 heure)
            }
            
            try:  # Gestion des erreurs pour l'envoi d'email
                msg = Message(  # Création du message email
                    'Réinitialisation de mot de passe',  # Sujet du message
                    recipients=[user.email],  # Destinataire
                    body=f'''Pour réinitialiser votre mot de passe, cliquez sur le lien :
{url_for('reset_password', token=token, _external=True)}  # Création de l'URL avec le token

Ce lien expirera dans 1 heure.
'''  # Corps du message
                )
                if not app.config['MAIL_SUPPRESS_SEND']:  # Si l'envoi d'email n'est pas supprimé
                    mail.send(msg)  # Envoi de l'email
                    flash("Email envoyé (si l'adresse existe)", "info")  # Message d'information (vague pour la sécurité)
                else:  # Si en mode développement
                    print(f"[DEV] Email simulé envoyé à {user.email}: {msg.body}")  # Affichage dans la console pour débug
                    flash("En développement: Lien affiché dans la console", "info")  # Message pour les développeurs
            except Exception as e:  # En cas d'erreur lors de l'envoi
                app.logger.error(f"Erreur email: {str(e)}")  # Journalisation de l'erreur
                flash("Erreur d'envoi d'email", "danger")  # Message d'erreur pour l'utilisateur
        
        return redirect(url_for('login'))  # Redirection vers la page de connexion (même si utilisateur inexistant, pour sécurité)
    
    return render_template('forgot_password.html')  # Rendu du template forgot_password.html

@app.route('/reset-password/<token>', methods=['GET', 'POST'])  # Route pour la réinitialisation du mot de passe avec le token
def reset_password(token):  # Fonction pour gérer la réinitialisation du mot de passe
    token_data = password_reset_tokens.get(token)  # Récupération des données associées au token
    
    if not token_data or token_data['expires'] < datetime.now():  # Si le token n'existe pas ou est expiré
        flash("Lien invalide ou expiré", "danger")  # Message d'erreur
        return redirect(url_for('forgot_password'))  # Redirection vers la page de mot de passe oublié
    
    if request.method == 'POST':  # Si le formulaire a été soumis
        user = User.query.get(token_data['user_id'])  # Récupération de l'utilisateur concerné
        new_password = request.form['password']  # Récupération du nouveau mot de passe
        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # Hachage et mise à jour du mot de passe
        db.session.commit()  # Enregistrement des modifications dans la base de données
        password_reset_tokens.pop(token)  # Suppression du token utilisé
        flash("Mot de passe réinitialisé avec succès", "success")  # Message de succès
        return redirect(url_for('login'))  # Redirection vers la page de connexion
    
    return render_template('reset_password.html', token=token)  # Rendu du template reset_password.html avec le token

@app.route('/dashboard')  # Route pour le tableau de bord
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:  # Vérification si l'utilisateur est connecté
        flash("Veuillez vous connecter", "warning")  # Message d'avertissement si non connecté
        return redirect(url_for('login'))  # Redirection vers la page de connexion
    
    user = User.query.get(session['user_id'])  # Récupération des informations de l'utilisateur
    
    result = None
    error = None
    
    if request.method == 'POST':  # Si le formulaire de calcul a été soumis
        try:
            Xa = float(request.form["Xa"])
            T = float(request.form["T"])
            result = calcul_diffusion(Xa, T)
        except ValueError as ve:
            error = str(ve)
        except Exception as e:
            error = f"Erreur de calcul : {str(e)}"
    
    return render_template('dashboard.html', user=user, result=result, error=error)

@app.route('/logout')  # Route pour la déconnexion
def logout():  # Fonction pour gérer la déconnexion
    session.pop('user_id', None)  # Suppression de l'ID utilisateur de la session
    flash("Déconnexion réussie", "info")  # Message de confirmation
    return redirect(url_for('index'))  # Redirection vers la page d'accueil


@app.route('/about')  # Route pour la page d'accueil
def about():  # Fonction pour gérer la page d'accueil
    return render_template('info.html')  # Rendu du template index.html

#calculator 
# Constantes
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
    Xa = float(request.args.get('Xa'))
    T = float(request.args.get('T'))
    Dab = float(request.args.get('Dab'))
    erreur = float(request.args.get('erreur'))
    lnDab = float(request.args.get('lnDab'))
    
    return render_template("resultat.html", Xa=Xa, T=T, Dab=Dab, erreur=erreur, lnDab=lnDab)

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('index'))

if __name__ == '__main__':  # Vérification si le script est exécuté directement
    app.run(debug=True)  # Lancement de l'application en mode debug