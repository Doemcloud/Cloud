import logging
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import uuid  # Для генерации API ключей
from datetime import datetime

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object('config.Config')  # Загружаем конфигурацию из файла config.py

db = SQLAlchemy(app)

# Модель пользователя с API ключом
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100), nullable=True)
    api_key = db.Column(db.String(100), unique=True, nullable=False)  # API ключ для авторизации

# Модель файла
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)  # Сохраненное имя файла
    original_filename = db.Column(db.String(100), nullable=False)  # Оригинальное имя файла
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Привязка к пользователю
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Дата загрузки
    is_shared = db.Column(db.Boolean, default=False)  # Файл доступен другим пользователям
    is_starred = db.Column(db.Boolean, default=False)  # Избранный файл
    is_deleted = db.Column(db.Boolean, default=False)  # Файл находится в корзине

# Главная страница с логином
@app.route('/')
def login_page():
    return render_template('index.html')

# Обработка логина через форму
@app.route('/login_form', methods=['POST'])
def login_form():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        error = "Неверный логин или пароль"
        return render_template('index.html', error=error)

    # Сохраняем API ключ в сессии после успешного логина
    session['user_id'] = user.id
    session['api_key'] = user.api_key
    return redirect(url_for('file_list'))

# Маршрут для регистрации нового пользователя
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    display_name = request.form.get('display_name')

    if User.query.filter_by(username=username).first():
        flash("User already exists", "error")
        return redirect(url_for('login_page'))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    api_key = str(uuid.uuid4())  # Генерация уникального API ключа
    new_user = User(username=username, password=hashed_password.decode('utf-8'), display_name=display_name,
                    api_key=api_key)

    db.session.add(new_user)
    db.session.commit()

    flash("Registration successful! Please log in.", "success")
    return redirect(url_for('login_page'))

# Страница с файлами пользователя
@app.route('/files')
def file_list():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login_page'))

    user = db.session.get(User, user_id)
    user_files = File.query.filter_by(owner_id=user_id).all()

    return render_template('files.html', current_user=user, files=user_files)

# Страница общих файлов
@app.route('/shared')
def shared_files():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login_page'))

    shared_files = File.query.filter_by(is_shared=True).all()

    return render_template('shared_files.html', files=shared_files, current_user=db.session.get(User, user_id))

# Страница избранных файлов
@app.route('/starred')
def starred_files():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login_page'))

    starred_files = File.query.filter_by(is_starred=True, owner_id=user_id).all()

    return render_template('starred_files.html', files=starred_files, current_user=db.session.get(User, user_id))

# Страница корзины
@app.route('/recycle')
def recycle_bin():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login_page'))

    deleted_files = File.query.filter_by(is_deleted=True, owner_id=user_id).all()

    return render_template('recycle_bin.html', files=deleted_files, current_user=db.session.get(User, user_id))

# Страница настроек с кнопкой выхода
@app.route('/settings')
def settings():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login_page'))

    user = db.session.get(User, user_id)
    return render_template('settings.html', current_user=user)

# Маршрут для выхода из аккаунта
@app.route('/logout')
def logout():
    session.clear()  # Очищаем сессию
    flash("You have been logged out.", "info")
    return redirect(url_for('login_page'))

# Проверка API ключа
def authenticate(api_key):
    user = User.query.filter_by(api_key=api_key).first()
    if user:
        return user
    else:
        logger.warning(f"Invalid API key used: {api_key}")
        return None

# API для загрузки файлов (с автоматической передачей API ключа из сессии)
@app.route('/api/upload', methods=['POST'])
def upload_file():
    api_key = session.get('api_key')  # Используем API ключ из сессии
    user = authenticate(api_key)

    if not user:
        return jsonify({"msg": "Invalid API key"}), 401

    if 'file' not in request.files:
        logger.error("No file part in request")
        return jsonify({"msg": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        logger.error("No selected file in request")
        return jsonify({"msg": "No selected file"}), 400

    # Проверяем наличие директории для файлов
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        logger.info(f"Directory {app.config['UPLOAD_FOLDER']} created")

    original_filename = file.filename  # Оригинальное имя файла
    filename = secure_filename(file.filename)  # Безопасное имя для хранения
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(file_path)
        logger.info(f"File saved at {file_path}")
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        return jsonify({"msg": "Failed to save file"}), 500

    new_file = File(filename=filename, original_filename=original_filename, owner_id=user.id)
    db.session.add(new_file)
    db.session.commit()

    return jsonify({"msg": "File uploaded successfully"}), 201

# API для скачивания файлов (с автоматической передачей API ключа из сессии)
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    api_key = session.get('api_key')  # Используем API ключ из сессии
    user = authenticate(api_key)

    if not user:
        return jsonify({"msg": "Invalid API key"}), 401

    file = File.query.filter_by(filename=filename, owner_id=user.id).first()
    if not file:
        logger.error(f"File {filename} not found or access denied for user {user.username}")
        return jsonify({"msg": "File not found or access denied"}), 404

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Добавление файла в избранное
@app.route('/file/star/<int:file_id>', methods=['POST'])
def star_file(file_id):
    file = File.query.get(file_id)
    if file:
        file.is_starred = True
        db.session.commit()
    return redirect(url_for('starred_files'))

# Удаление файла (перемещение в корзину)
@app.route('/file/remove/<int:file_id>', methods=['GET', 'POST'])  # Изменено на remove
def remove_file(file_id):
    file = File.query.get(file_id)
    if file:
        file.is_deleted = True
        db.session.commit()
    return redirect(url_for('file_list'))

# Маршрут для "Поделиться"
@app.route('/file/share/<int:file_id>', methods=['GET'])
def share_file(file_id):
    file = File.query.get(file_id)
    if file:
        file.is_shared = True
        db.session.commit()
    return redirect(url_for('file_list'))

# Запуск сервера
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # создание таблиц в базе данных
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
