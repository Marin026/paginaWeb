from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin


db = SQLAlchemy()

# Tabla de asociación para la relación muchos a muchos de juegos descargados
downloads = db.Table(
    'downloads',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('game_id', db.Integer, db.ForeignKey('game.id'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    documento = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    
    # Relaciones
    creator_games = db.relationship('Game', backref='creator', lazy=True, cascade='all, delete-orphan')
    donations_made = db.relationship('Donation', backref='donor', lazy=True, cascade='all, delete-orphan', foreign_keys='Donation.donor_id')
    received_donations = db.relationship('Donation', backref='creator', lazy=True, foreign_keys='Donation.creator_id')
    comments = db.relationship('Comment', backref='user', lazy=True, cascade='all, delete-orphan')
    downloaded_games = db.relationship(
        'Game', secondary=downloads, lazy='subquery',
        backref=db.backref('downloaded_by', lazy=True)
    )

class Game(db.Model):
    __tablename__ = 'game'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # 🔹 Nuevos campos opcionales (especificaciones del juego)
    genre = db.Column(db.String(100), nullable=True)          # Ejemplo: "Acción", "Aventura", "RPG"
    platform = db.Column(db.String(100), nullable=True)       # Ejemplo: "PC", "PlayStation", "Xbox"
    size = db.Column(db.String(50), nullable=True)            # Ejemplo: "2.5 GB"
    developer = db.Column(db.String(100), nullable=True)      # Ejemplo: "Nintendo", "Ubisoft"
    release_date = db.Column(db.String(50), nullable=True)    # Ejemplo: "2024-11-12"

    # Relaciones
    donations = db.relationship('Donation', backref='game', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='game', lazy=True, cascade='all, delete-orphan')
    
class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)

class Donation(db.Model):
    __tablename__ = 'donation'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_ref = db.Column(db.String(100), unique=True, nullable=True)
    status = db.Column(db.String(20), default='PENDING', nullable=False)
    
 
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(hours=1)) # Token expira en 1 hora
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))    
    
class Notification(db.Model):
    """Modelo para almacenar los avances y notificaciones publicadas por los Creadores."""
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relación para acceder a los datos del creador que publicó la notificación
    creator = db.relationship('User', backref=db.backref('notifications_published', lazy=True))
    
class LoginLog(db.Model):
    __tablename__ = 'login_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relación opcional para acceder al usuario desde el log
    user = db.relationship('User', backref=db.backref('login_logs', lazy=True))