from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from datetime import datetime, timedelta

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
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
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
 
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(hours=1)) # Token expira en 1 hora
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))    