from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from config import Config
from flask_mail import Mail, Message
import random
from datetime import datetime

from flask_login import  login_required, LoginManager, login_user, current_user
from config import WOMPI_PUBLIC_KEY, WOMPI_INTEGRITY_KEY, WOMPI_REDIRECT_URL, WOMPI_CURRENCY
from models import db, User, Game, Comment, Donation, PasswordResetToken, Notification, downloads
from sqlalchemy import func, text, extract
from collections import defaultdict
import traceback  
import smtplib
import json
import uuid
import hashlib

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



admin_bp = Blueprint('admin', __name__)


login_manager = LoginManager()       
login_manager.init_app(app)         
login_manager.login_view = 'login'

# ✅ REGISTRAR BLUEPRINT DEL ADMINISTRADOR (necesario para las gráficas)

@login_manager.user_loader
def load_user(user_id):
    """Función requerida para recargar el objeto User desde la DB
    dado el ID almacenado en la sesión."""
    return User.query.get(int(user_id))

WOMPI_PUBLIC_KEY = 'pub_prod_rsFWKqoo2nBPc1ywo92AufU32xCP9Vaf'
WOMPI_INTEGRITY_KEY = 'prv_prod_Wyki3bEfGsCbWSdXDmTO3TNQkeok31hU'
WOMPI_REDIRECT_URL = 'https://levelup.isladigital.xyz/donacion_finalizada'
WOMPI_CURRENCY = 'COP'

def send_notification_email(subject, recipients, html_body):
    """Función de ayuda para enviar un correo electrónico con Flask-Mail."""
    try:
        
        msg = Message(subject,
                      sender=app.config.get('MAIL_DEFAULT_SENDER', 'tu_correo@ejemplo.com'),
                      recipients=recipients,
                      html=html_body)
        # Envía el correo
        mail.send(msg) 
        return True
    except Exception as e:
        print(f"Error al enviar correo: {e}")
        # En un entorno de producción, podrías usar un logger aquí
        return False



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
    return redirect(url_for('login'))

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
        genre = request.form.get('game-genre')
        platform = request.form.get('game-platform')
        image = request.files.get('game-image')
        game_file = request.files.get('game-file')

        if not all([game_name, description, image, game_file]):
            flash("Todos los campos principales son obligatorios", "error")
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

        # 🔹 Calcular tamaño del archivo
        file_size_bytes = os.path.getsize(file_path)
        if file_size_bytes < 1024 * 1024:
            file_size = f"{file_size_bytes / 1024:.2f} KB"
        else:
            file_size = f"{file_size_bytes / (1024 * 1024):.2f} MB"

        # 🔹 Obtener nombre del desarrollador (usuario actual)
        user = User.query.get(session['user_id'])
        developer_name = user.username if user else "Desconocido"

        # 🔹 Fecha automática de lanzamiento (día de subida)
        release_date = datetime.now().strftime("%Y-%m-%d")

        # Guardar en la base de datos
        new_game = Game(
            name=game_name,
            description=description,
            genre=genre,
            platform=platform,
            size=file_size,
            developer=developer_name,
            release_date=release_date,
            image_url=f'uploads/games/images/{image_filename}',
            file_path=f'uploads/games/files/{file_filename}',
            creator_id=session['user_id']
        )

        db.session.add(new_game)
        db.session.commit()

        flash("Juego subido correctamente", "success")
        return redirect(url_for('home_creador'))

    return render_template('formu.html')

# --- ELIMINAR JUEGO ---
@app.route('/delete_game/<int:game_id>', methods=['POST'])
def delete_game(game_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para eliminar un juego.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    game = Game.query.get_or_404(game_id)

    # Verificar que el usuario sea el creador del juego o un administrador
    if game.creator_id != user.id and user.role != 'Administrador':
        flash('No tienes permiso para eliminar este juego.', 'error')
        return redirect(url_for('home_creador'))

    # Eliminar archivos asociados (imagen y archivo del juego)
    try:
        if game.image_url:
            image_path = os.path.join('static', game.image_url)
            if os.path.exists(image_path):
                os.remove(image_path)

        if game.file_path:
            file_path = os.path.join('static', game.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
    except Exception as e:
        print(f"Error eliminando archivos: {e}")

    # Eliminar registro de la base de datos
    db.session.delete(game)
    db.session.commit()

    flash('Juego eliminado correctamente.', 'success')
    if user.role == 'Administrador':
        return redirect(url_for('admin_panel'))
    return redirect(url_for('home_creador'))


# --- DONACIONES ---



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
# ... (Función admin_panel completa) ...
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder.', 'error')
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    
    if not user or user.role != 'Administrador':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))
        
    users = User.query.all()
    games = Game.query.all()
    donations = Donation.query.all()
    
    return render_template('admin_dashboard.html', users=users, games=games, donations=donations)

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

#-- DETALLE DEL JUEGO ---
@app.route('/game/<int:game_id>')
def ver_juego(game_id):
    # Buscar el juego en la base de datos
    game = Game.query.get_or_404(game_id)

    # (Opcional) Si tienes relación con comentarios, puedes traerlos así:
    comentarios = Comment.query.filter_by(game_id=game_id).all()

    return render_template('detalle_juego.html', game=game, comentarios=comentarios)



    # ---------------------------------------------------------------------JDavid ------------------------------------------------------------------------------------------------------------------------------
    
@app.route('/creador/publicar_avance', methods=['GET', 'POST'])
def publicar_avance():
# ... (Función publicar_avance completa) ...
    """Permite al Creador publicar un avance/notificación y notificar por correo."""
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder.', 'error')
        return redirect(url_for('login'))

    creator = User.query.get(session['user_id'])
    if creator.role != 'Creador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        image_url = None
        if 'image' in request.files and request.files['image'].filename != '':
            file = request.files['image']
            filename = secure_filename(file.filename)
            # Asegura un nombre de archivo único
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            image_url = unique_filename

        # 1. Guardar la notificación en la base de datos (para la vista en la página)
        new_notification = Notification(
            title=title,
            content=content,
            image_url=image_url,
            creator_id=creator.id
        )
        db.session.add(new_notification)
        db.session.commit()

        # 2. Enviar notificaciones por correo electrónico a todos los usuarios/creadores
        # Obtener todos los correos registrados
        all_users = User.query.with_entities(User.email).all()
        recipients = [user[0] for user in all_users]

        # Crear el cuerpo del correo (HTML)
        image_html = f'<img src="{request.url_root}static/uploads/{image_url}" alt="Avance de Creador" style="max-width: 100%; height: auto;">' if image_url else ''
        email_html = render_template('email_notification.html', 
                                     creator_name=creator.username,
                                     notification_title=title, 
                                     notification_content=content,
                                     notification_image_html=image_html)
        
        send_notification_email(
            subject=f"[AVANCE DE CREADOR] {title}",
            recipients=recipients,
            html_body=email_html
        )
        
        flash('Avance publicado y notificaciones por correo enviadas exitosamente.', 'success')
        return redirect(url_for('home_creador'))

    # Renderiza la plantilla del formulario de publicación
    return render_template('publicar_avance.html', creator=creator)


@app.route('/delete_notification/<int:notif_id>', methods=['POST'])
def delete_notification(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    # Solo creador o admin pueden borrar
    if notif.creator_id != current_user.id and not getattr(current_user, 'is_admin', False):
        abort(403)

    # Eliminar imagen si existe
    if notif.image_url:
        image_path = os.path.join(app.root_path, 'static/uploads', notif.image_url)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(notif)
    db.session.commit()

    return redirect(url_for('home_usuario'))



@app.route('/donaciones', methods=['GET', 'POST'])
def donaciones():
    try:
        # --- Cargar datos necesarios para mostrar en la vista ---
        creators = User.query.filter_by(role='Creador').all()
        games = Game.query.all()
    except Exception as e:
        flash(f'Error al cargar datos: {e}', 'error')
        return redirect(url_for('home_usuario'))

    if request.method == 'POST':
        try:
            print(">>> POST /donaciones recibido.")

            # 🔹 Forzar lectura de JSON aunque el header sea incorrecto
            try:
                data = request.get_json(force=True)
                print(">>> Datos recibidos (JSON):", data)
                creator_id = data.get('creator_id')
                game_id = data.get('game_id')
                amount_str = data.get('amount')
            except Exception as e:
                print("⚠️ No se pudo parsear JSON, intentando con form:", e)
                creator_id = request.form.get('creator_id')
                game_id = request.form.get('game_id')
                amount_str = request.form.get('amount')

            # --- Validaciones ---
            if not creator_id or not amount_str:
                raise ValueError("Faltan datos: creator_id o amount")

            if 'user_id' not in session:
                raise KeyError("Usuario no autenticado")

            amount = float(amount_str)
            if amount < 100:
                raise ValueError("El monto mínimo de donación es 100 COP")

            if not WOMPI_PUBLIC_KEY or not WOMPI_INTEGRITY_KEY:
                raise ValueError("Claves de Wompi no configuradas correctamente")

            # --- Datos de la transacción ---
            amount_in_cents = int(amount * 100)
            currency = WOMPI_CURRENCY
            reference = f"DON-{session['user_id']}-{creator_id}-{uuid.uuid4().hex[:8]}"

            # --- Crear registro de donación PENDING ---
            new_donation = Donation(
                donor_id=session['user_id'],
                creator_id=creator_id,
                game_id=game_id,
                amount=amount,
                transaction_ref=reference,
                status='PENDING'
            )
            db.session.add(new_donation)
            db.session.commit()
            print(f"✅ Donación creada (PENDING) con ID {new_donation.id}, ref: {reference}")

            # --- Generar firma SHA256 para Wompi ---
            cadena = f"{reference}{amount_in_cents}{currency}{WOMPI_INTEGRITY_KEY}"
            signature = hashlib.sha256(cadena.encode('utf-8')).hexdigest()

            wompi_params = {
                "currency": currency,
                "amountInCents": amount_in_cents,
                "reference": reference,
                "publicKey": WOMPI_PUBLIC_KEY,
                "signature": signature,
                "redirectUrl": WOMPI_REDIRECT_URL,
                "customerData": {
                    "email": db.session.get(User, session['user_id']).email,
                    "fullName": db.session.get(User, session['user_id']).username
                },
                "data": {
                    "donor_id": session['user_id'],
                    "creator_id": creator_id,
                    "game_id": game_id
                }
            }

            print(">>> wompi_params_json generado:", wompi_params)

            # --- Si fue petición JSON (fetch desde JS) ---
            if request.is_json or request.headers.get("Content-Type") == "application/json":
                return jsonify({"success": True, "wompi": wompi_params}), 200

            # --- Si fue formulario HTML normal ---
            return render_template("wompi_redirect.html", wompi_params=wompi_params)

        except Exception as e:
            db.session.rollback()
            print("❌ Error en /donaciones:", e)
            traceback.print_exc()

            if request.is_json:
                return jsonify({"success": False, "error": str(e)}), 400

            flash(f"Error al iniciar el pago: {e}", "error")
            return render_template("wompi_redirect.html", wompi_params={})

    # --- GET: mostrar formulario ---
    return render_template(
        "donaciones.html",
        creators=creators,
        games=games
    )



@app.route('/donacion_finalizada')
def donacion_finalizada():
    status = request.args.get('status', 'ERROR')
    transaction_id = request.args.get('id', 'N/A')

    if status == 'APPROVED':
        flash('🎉 ¡Donación Exitosa! Gracias por tu apoyo.', 'success')
    elif status == 'PENDING':
        flash('⌛ Tu pago está en estado pendiente. Recibirás una notificación cuando se apruebe.', 'warning')
    else:
        flash('❌ La donación no pudo completarse o fue cancelada.', 'error')

    return render_template('wompi_return.html', status=status, transaction_id=transaction_id)

@app.route('/wompi_events', methods=['POST'])
def wompi_events():
    event = request.get_json()
    
    
    transaction = event.get('data', {}).get('transaction', {})
    status = transaction.get('status')
    reference = transaction.get('reference')
    
    if status == 'APPROVED':
        # Obtener los datos necesarios de la transacción (monto, IDs, etc.)
        amount = transaction.get('amount_in_cents') / 100
        # Los IDs están en el campo 'data' que enviamos en el paso anterior
        transaction_data = transaction.get('data', {}) 
        donor_id = transaction_data.get('donor_id')
        creator_id = transaction_data.get('creator_id')
        game_id = transaction_data.get('game_id')
        
        # 3. Guardar la donación final en la base de datos
        existing_donation = Donation.query.filter_by(transaction_ref=reference).first()

        if not existing_donation:
            # Crear la nueva donación SOLO si no existe (para evitar duplicados)
            new_donation = Donation(
                amount=amount, 
                donor_id=donor_id, 
                creator_id=creator_id, 
                game_id=game_id, 
                transaction_ref=reference,
                status='APPROVED'
            )
            db.session.add(new_donation)
            db.session.commit()
         
    elif status in ['DECLINED', 'VOIDED', 'ERROR']:
       pass
        
    return jsonify({"status": "OK"}), 200 


@app.route('/wompi_events_redirect', methods=['GET'])
def wompi_events_redirect():
    transaction_id = request.args.get('id') 
    
    flash('Tu pago fue procesado. Revisa el estado en tu historial.', 'info')
    return redirect(url_for('home_user')) # O a donde quieras que el usuario vaya
@app.route('/create-payment-preference', methods=['POST'])

@app.route('/wompi_redirect')
def wompi_redirect():
    status = request.args.get('status', 'ERROR')
    transaction_id = request.args.get('id', 'N/A')
    return render_template('wompi_return.html', status=status, transaction_id=transaction_id)


def create_payment_preference():
    """
    Ruta llamada por JavaScript para iniciar la transacción con la pasarela de pago.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Usuario no autenticado'}), 401

    try:
        # Los datos se reciben en formato JSON (desde la llamada Fetch en donaciones.html)
        data = request.json
        amount = data.get('amount')
        creator_id = data.get('creator_id')
        game_id = data.get('game_id')
        
        # Validación de datos
        if not amount or (not creator_id and not game_id):
            return jsonify({'error': 'Faltan datos de donación.'}), 400

        try:
            amount = float(amount)
        except ValueError:
            return jsonify({'error': 'Monto inválido.'}), 400
            
        if amount <= 0:
            return jsonify({'error': 'El monto debe ser positivo.'}), 400

        donor_id = session['user_id']
        
       
        external_reference = f"DONATION-{donor_id}-{creator_id or 0}-{game_id or 0}-{uuid.uuid4()}"
        
        # 2. Configuración de la preferencia (Ejemplo con Mercado Pago o Wompi)
        preference_data = {
            "items": [
                {
                    "title": f"Donación a Creador: {creator_id or 'General'}",
                    "quantity": 1,
                    # Los proveedores esperan el monto en la unidad base (centavos/pesos), revisa su documentación
                    "unit_price": amount, 
                    "currency_id": "COP" 
                }
            ],
            # URL a la que la pasarela notificará la confirmación del pago (Webhook)
            "notification_url": url_for('payment_webhook', _external=True),
            # URL a la que el usuario es redirigido después de un pago
            "back_urls": {
                "success": url_for('home_usuario', _external=True, status='payment_success'),
                "failure": url_for('donaciones', _external=True, status='payment_failure'),
            },
            "external_reference": external_reference,
            # Guardar metadatos cruciales para usar en el Webhook
            "metadata": {
                "donor_id": donor_id,
                "creator_id": creator_id,
                "game_id": game_id,
                "amount": amount
            }
        }
        
        
        payment_url = f"https://checkout.example.com/pago?ref={external_reference}&amount={amount}"
        return jsonify({
            'success': True, 
            'payment_url': payment_url,
            'external_reference': external_reference
        }), 200

    except Exception as e:
        app.logger.error(f"Error en create_payment_preference: {e}")
        return jsonify({'error': 'Error interno del servidor.'}), 500


# =========================================================================
# === NUEVA RUTA: Webhook para confirmar el pago (La pasarela llama a esta) ===
# =========================================================================
@app.route('/webhook-pago', methods=['POST'])
def payment_webhook():
    """
    Esta ruta es llamada por el servidor de la pasarela de pago (ej: Mercado Pago) 
    para notificar el estado final de una transacción.
    """
    try:
        amount = 5000.0 # Monto confirmado
        donor_id = 1 
        creator_id = 2 
        game_id = None 
        transaction_id = str(uuid.uuid4()) # ID de la transacción del proveedor

        # 2. CREACIÓN FINAL DEL OBJETO DONATION (SOLO si el pago fue 'approved')
        new_donation = Donation(
            donor_id=donor_id,
            creator_id=creator_id,
            game_id=game_id,
            amount=amount,
            # Se recomienda agregar 'transaction_id' al modelo Donation
            donation_date=datetime.utcnow() 
        )
        
        db.session.add(new_donation)
        db.session.commit()
        
        # Devolver un 200 OK es fundamental para que la pasarela no reintente.
        return '', 200 
    
    except Exception as e:
        app.logger.error(f"Error al procesar webhook de pago: {e}")
        return '', 500 # Devolver un 500 para que la pasarela reintente.


@admin_bp.route('/admin/dashboard/data')
def dashboard_data():
    """Genera los datos estadísticos del panel de administración."""
    # --- Donaciones por mes ---
    donations_month = (
        db.session.query(
            extract('month', Donation.timestamp).label('month'),
            func.sum(Donation.amount)
        )
        .group_by('month')
        .order_by('month')
        .all()
    )
    donations_month_labels = [str(int(row[0])) for row in donations_month]
    donations_month_data = [float(row[1]) for row in donations_month]

    # --- Donaciones por semana ---
    donations_week = (
    db.session.query(
        func.date_format(Donation.timestamp, '%Y-%u').label('week'),  # <-- cambiado
        func.sum(Donation.amount)
            )
            .group_by('week')
            .order_by('week')
            .all()
        )
    donations_week_labels = [row[0] for row in donations_week]
    donations_week_data = [float(row[1]) for row in donations_week]
    logins_by_role = (
        db.session.query(User.role, func.count(User.id))
        .group_by(User.role)
        .all()
    )
    logins_labels = [row[0] for row in logins_by_role]
    logins_data = [row[1] for row in logins_by_role]

    # --- Top 10 juegos más descargados ---
    downloads_count = (
        db.session.query(
            Game.name,
            func.count(downloads.c.game_id).label('count')
        )
        .join(downloads, Game.id == downloads.c.game_id)
        .group_by(Game.id)
        .order_by(func.count(downloads.c.game_id).desc())
        .limit(10)
        .all()
    )
    downloads_labels = [row[0] for row in downloads_count]
    downloads_data = [row[1] for row in downloads_count]

    # --- Actividad diaria del mes actual ---
    today = datetime.utcnow()
    start_of_month = today.replace(day=1)
    next_month = (start_of_month + timedelta(days=32)).replace(day=1)

    donations_daily = (
        db.session.query(
            func.date(Donation.timestamp).label('date'),
            func.sum(Donation.amount).label('total')
        )
        .filter(Donation.timestamp >= start_of_month, Donation.timestamp < next_month)
        .group_by('date')
        .order_by('date')
        .all()
    )
    donation_daily_dict = {str(row.date): float(row.total or 0) for row in donations_daily}

    downloads_daily = []
    try:
        downloads_daily = db.session.execute(text("""
            SELECT DATE(timestamp) AS date, COUNT(*) AS total
            FROM downloads
            WHERE timestamp >= :start AND timestamp < :end
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp)
        """), {'start': start_of_month, 'end': next_month}).fetchall()
    except Exception as e:
        print("⚠️ No se encontró columna timestamp en downloads:", e)
    downloads_daily_dict = {str(row.date): row.total for row in downloads_daily}

    logins_daily_dict = {}

    days_in_month = [(start_of_month + timedelta(days=i)).date() for i in range((next_month - start_of_month).days)]
    labels_daily = [str(day) for day in days_in_month]

    activity_day = {
        'labels': labels_daily,
        'donations': [donation_daily_dict.get(str(day), 0) for day in days_in_month],
        'downloads': [downloads_daily_dict.get(str(day), 0) for day in days_in_month],
        'logins': [logins_daily_dict.get(str(day), 0) for day in days_in_month],
    }

    return jsonify({
        'donations_month': {'labels': donations_month_labels, 'data': donations_month_data},
        'donations_week': {'labels': donations_week_labels, 'data': donations_week_data},
        'logins': {'labels': logins_labels, 'data': logins_data},
        'downloads': {'labels': downloads_labels, 'data': downloads_data},
        'activity_day': activity_day
    })

# ✅ REGISTRA EL BLUEPRINT AQUÍ (después de definir todas sus rutas)
app.register_blueprint(admin_bp)

# --- MAIN ---
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)