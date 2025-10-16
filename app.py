from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from config import Config
from models import db, User, Game, Comment, Donation, PasswordResetToken 
from flask_mail import Mail, Message
import random

# --- Inicialización de la app Flask ---
app = Flask(__name__)
app.config.from_object(Config)

# --- Configuración de subida de archivos ---
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'games')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2 GB máximo
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Inicialización de extensiones ---
db.init_app(app)
mail = Mail(app)

# --- Crear carpeta de subidas si no existe ---
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# --- Crear usuario administrador por defecto ---
def create_default_admin():
    """Crea un usuario administrador por defecto si no existe."""
    with app.app_context():
        admin_user = User.query.filter_by(documento='123456789').first()
        if not admin_user:
            hashed_password = generate_password_hash('4512', method='pbkdf2:sha256')
            new_admin = User(
                username='edi',
                email='admin@levelup.com',
                documento='123456789',
                password=hashed_password,
                role='Administrador'
            )
            db.session.add(new_admin)
            db.session.commit()

# --- Inicialización de la base de datos ---
with app.app_context():
    db.create_all()
    create_default_admin()


# --- RUTAS PRINCIPALES ---
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


# --- REGISTRO ---
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
            flash('El correo electrónico ya está registrado.', 'error')
        elif existing_user_by_documento:
            flash('El documento ya está registrado.', 'error')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, documento=documento, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


# --- LOGIN ---
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


# --- LOGOUT ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('login'))


# --- SUBIR JUEGO ---
@app.route('/upload_game', methods=['GET', 'POST'])
def upload_game():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para subir un juego.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        game_name = request.form['game-name']
        description = request.form['game-description']
        image = request.files.get('game-image')
        game_file = request.files.get('game-file')

        if not all([game_name, description, image, game_file]):
            flash("Todos los campos son obligatorios", "error")
            return redirect(url_for('home_creador'))

        # Guardar imagen
        image_filename = secure_filename(image.filename)
        image_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'images')
        os.makedirs(image_folder, exist_ok=True)
        image_path = os.path.join(image_folder, image_filename)
        image.save(image_path)

        # Guardar archivo del juego
        file_filename = secure_filename(game_file.filename)
        file_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'files')
        os.makedirs(file_folder, exist_ok=True)
        file_path = os.path.join(file_folder, file_filename)
        game_file.save(file_path)

        # Guardar en la base de datos
        new_game = Game(
            name=game_name,
            description=description,
            image_url=f'uploads/games/images/{image_filename}',
            file_path=f'uploads/games/files/{file_filename}',
            creator_id=session['user_id']
        )
        db.session.add(new_game)
        db.session.commit()

        flash("Juego subido correctamente", "success")
        return redirect(url_for('home_creador'))

    return render_template('formu.html')


# --- DONACIONES ---
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
            flash('La cantidad debe ser positiva.', 'error')
            return redirect(url_for('donaciones'))

        donor_id = session['user_id']
        new_donation = Donation(donor_id=donor_id, creator_id=creator_id, game_id=game_id, amount=amount)
        db.session.add(new_donation)
        db.session.commit()

        flash('¡Donación realizada con éxito!', 'success')
        return redirect(url_for('home_usuario'))

    return render_template('donaciones.html', creators=creators, games=games,
                           preselected_creator_id=preselected_creator_id,
                           preselected_game_id=preselected_game_id)


# --- HISTORIAL DE DONACIONES ---
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


# --- PANELES DE USUARIO ---
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


# --- EDITAR PERFIL ---
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


# --- RECUPERACIÓN DE CONTRASEÑA ---
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
            flash('El código es incorrecto.', 'error')
            return render_template('verify_code.html', email=email)

        if reset_token.expiration < datetime.utcnow():
            flash('El código ha expirado.', 'error')
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


# --- MAIN ---
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
