from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from config import Config
from models import db, User, Game, Comment, Donation, PasswordResetToken 
from flask_mail import Mail, Message
import uuid
import random

app = Flask(__name__)
app.config.from_object(Config)

mail = Mail(app)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)

def create_default_admin():
    """Función para crear un usuario administrador por defecto si no existe."""
    with app.app_context():
        admin_user = User.query.filter_by(documento='123456789').first()
        if not admin_user:
            hashed_password = generate_password_hash('4512', method='pbkdf2:sha256')
            new_admin = User(username='edi', email='admin@levelup.com', documento='123456789', password=hashed_password, role='Administrador')
            db.session.add(new_admin)
            db.session.commit()

# --- CAMBIO IMPORTANTE: Solución al error ---
# Reemplazamos @app.before_first_request con with app.app_context()
with app.app_context():
    db.create_all()
    create_default_admin()
# --- FIN DEL CAMBIO ---

@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.role == 'Usuario':
                return redirect(url_for('home_usuario'))
            elif user.role == 'Creador':
                return redirect(url_for('home_creador'))
            elif user.role == 'Administrador':
                return redirect(url_for('admin_panel'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        documento = request.form['documento']
        password = request.form['password']
        role = request.form['role']
        
        existing_user_by_username = User.query.filter_by(username=username).first()
        existing_user_by_email = User.query.filter_by(email=email).first()
        existing_user_by_documento = User.query.filter_by(documento=documento).first()

        if existing_user_by_username:
            flash('El nombre de usuario ya existe. Por favor, elige otro.', 'error')
        elif existing_user_by_email:
            flash('El correo electrónico ya está registrado. Por favor, usa otro.', 'error')
        elif existing_user_by_documento:
            flash('El documento ya está registrado. Por favor, usa otro.', 'error')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, documento=documento, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.role == 'Usuario':
                return redirect(url_for('home_usuario'))
            elif user.role == 'Creador':
                return redirect(url_for('home_creador'))
            elif user.role == 'Administrador':
                return redirect(url_for('admin_panel'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('login'))

@app.route('/donaciones', methods=['GET', 'POST'])
def donaciones():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para hacer una donación.', 'error')
        return redirect(url_for('login'))
        
    creators = User.query.filter_by(role='Creador').all()
    games = Game.query.all()
    
    preselected_creator_id = request.args.get('creator_id', None)
    preselected_game_id = request.args.get('game_id', None)
    
    if request.method == 'POST':
        creator_id = request.form.get('creator_id')
        game_id = request.form.get('game_id')
        amount = request.form.get('amount')
        
        try:
            amount = float(amount)
        except (ValueError, TypeError):
            flash('La cantidad debe ser un número válido.', 'error')
            return redirect(url_for('donaciones', creator_id=creator_id, game_id=game_id))
            
        if amount <= 0:
            flash('La cantidad debe ser un valor positivo.', 'error')
            return redirect(url_for('donaciones', creator_id=creator_id, game_id=game_id))
            
        donor_id = session['user_id']
        
        new_donation = Donation(
            donor_id=donor_id,
            creator_id=creator_id,
            game_id=game_id,
            amount=amount
        )
        
        db.session.add(new_donation)
        db.session.commit()
        
        flash('¡Donación realizada con éxito!', 'success')
        return redirect(url_for('home_usuario'))
        
    return render_template('donaciones.html', creators=creators, games=games, preselected_creator_id=preselected_creator_id, preselected_game_id=preselected_game_id)

@app.route('/donations/history')
def donation_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if user.role != 'Creador':
        flash('No tienes permiso para ver esta página.', 'error')
        return redirect(url_for('home'))
        
    donations = Donation.query.filter_by(creator_id=user.id).all()
    
    return render_template('donations_history.html', donations=donations)

@app.route('/home_usuario')
def home_usuario():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    if not user or user.role != 'Usuario':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))
        
    games_uploaded = Game.query.all()
    
    return render_template('homeUser.html', user=user, all_games=games_uploaded)

@app.route('/home_creador')
def home_creador():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    if not user or user.role != 'Creador':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))
        
    creator_games = Game.query.filter_by(creator_id=user.id).all()
    
    return render_template('homeCreador.html', user=user, creator_games=creator_games)

@app.route('/admin_panel')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    if not user or user.role != 'Administrador':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))
        
    users = User.query.all()
    games = Game.query.all()
    donations = Donation.query.all()
    
    return render_template('admin.html', users=users, games=games, donations=donations)

@app.route('/upload_game', methods=['GET', 'POST'])
def upload_game():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para subir un juego.', 'error')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        game_name = request.form['game-name']
        game_description = request.form['game-description']
        
        if 'game-image' in request.files:
            file = request.files['game-image']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                new_game = Game(
                    name=game_name,
                    description=game_description,
                    image_url=filename,
                    creator_id=session['user_id']
                )
                
                db.session.add(new_game)
                db.session.commit()
                flash('Juego subido exitosamente.', 'success')
                return redirect(url_for('home_creador'))
            
    return render_template('formu.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        new_password = request.form['password']

        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash('Perfil actualizado con éxito.', 'success')
        
        if user.role == 'Usuario':
            return redirect(url_for('home_usuario'))
        elif user.role == 'Creador':
            return redirect(url_for('home_creador'))
            
    return render_template('edit_profile.html', user=user)

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            PasswordResetToken.query.filter_by(user_id=user.id).delete()
            db.session.commit()
            
            code = str(random.randint(100000, 999999))
            
            new_token = PasswordResetToken(user_id=user.id, token=code, expiration=datetime.utcnow() + timedelta(minutes=15))
            db.session.add(new_token)
            db.session.commit()
            
            msg = Message(
                'Código de Restablecimiento de Contraseña',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[user.email]
            )
            msg.html = render_template('password_reset_email.html', username=user.username, code=code)
            
            try:
                mail.send(msg)
                flash('Se ha enviado un código de verificación a tu correo electrónico.', 'success')
                return redirect(url_for('verify_code', email=email))
            except Exception as e:
                flash(f'Error al enviar el correo: {e}', 'error')
        else:
            flash('Si el correo electrónico existe, se ha enviado un código de verificación.', 'info')

    return render_template('request_password_reset.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Correo electrónico no encontrado.', 'error')
            return redirect(url_for('verify_code'))
            
        reset_token = PasswordResetToken.query.filter_by(user_id=user.id, token=code).first()
        
        if not reset_token:
            flash('El código es incorrecto. Intenta de nuevo.', 'error')
            return render_template('verify_code.html', email=email)
        
        if reset_token.expiration < datetime.utcnow():
            flash('El código ha expirado. Por favor, solicita uno nuevo.', 'error')
            return redirect(url_for('request_password_reset'))
            
        return redirect(url_for('reset_password_code', token=reset_token.token))
        
    email = request.args.get('email', '')
    return render_template('verify_code.html', email=email)
    
@app.route('/reset_password_code/<token>', methods=['GET', 'POST'])
def reset_password_code(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or reset_token.expiration < datetime.utcnow():
        flash('El enlace es inválido o ha expirado.', 'error')
        return redirect(url_for('request_password_reset'))
        
    user = reset_token.user
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        
        if not new_password:
            flash('La contraseña no puede estar vacía.', 'error')
            return render_template('reset_password.html', token=token)
        
        user.password = generate_password_hash(new_password)
        
        db.session.delete(reset_token)
        db.session.commit()
        
        flash('Tu contraseña ha sido actualizada exitosamente.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    # El db.create_all() ya no es necesario aquí si se usa el contexto de aplicación arriba
    app.run(debug=True, host="0.0.0.0", port=5000)