from flask import Flask, render_template, session, request, redirect, url_for, flash, g, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from mysqldb import DBConnector
from functools import wraps
import os
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')

app.config['UPLOAD_FOLDER'] = 'static/photos'
app.config['ALLOWED_EXTENSIONS'] = {'jpeg', 'jpg', 'png', 'gif'}

# Database connector
db_connector = DBConnector(app)

# Flask Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message = 'Войдите, чтобы продолжить.'
login_manager.login_message_category = 'warning'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, login, role):
        self.id = user_id
        self.login = login
        self.role = role

# Decorator for admin access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Password validation function
def validate_create_password(password, confirm_password):
    errors = {}
    if len(password) < 8 or len(password) > 128:
        errors['password'] = 'Пароль должен быть от 8 до 128 символов.'
    if not any(c.isupper() for c in password):
        errors['password'] = 'Пароль должен содержать хотя бы одну заглавную букву.'
    if not any(c.islower() for c in password):
        errors['password'] = 'Пароль должен содержать хотя бы одну строчную букву.'
    if not any(c.isdigit() for c in password):
        errors['password'] = 'Пароль должен содержать хотя бы одну цифру.'
    if any(c.isspace() for c in password):
        errors['password'] = 'Пароль не должен содержать пробелы.'
    if password != confirm_password:
        errors['confirm_password'] = 'Пароли не совпадают.'
    return errors

@login_manager.user_loader
def load_user(user_id):
    query = 'SELECT id, login, role FROM users WHERE id=%s'
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
    return User(user.id, user.login, user.role) if user else None

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/photos', methods=['GET'])
def photos():
    sort_by = request.args.get('sort_by', 'date_added')
    author_id = request.args.get('author', None)
    
    # Query for photos with optional filters
    filters = []
    query = 'SELECT id, title, image_uuid, image_ext FROM photos'

    if author_id:
        filters.append(f"author_id = {author_id}")

    if filters:
        query += ' WHERE ' + ' AND '.join(filters)

    # Sorting
    query += ' ORDER BY year DESC' if sort_by == 'date_written' else ' ORDER BY id DESC'

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        photos = cursor.fetchall()

    # Query for authors
    authors_query = 'SELECT id, name FROM authors'
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(authors_query)
        authors = cursor.fetchall()

    return render_template('photos.html', photos=photos, authors=authors, current_sort=sort_by, current_author=author_id)

@app.route('/photo/<int:photo_id>')
@login_required
def photo_detail(photo_id):
    query = '''SELECT p.*, a.name as author_name 
               FROM photos p LEFT JOIN authors a ON p.author_id = a.id 
               WHERE p.id=%s'''
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (photo_id,))
        photo = cursor.fetchone()
        
    if photo is None:
        flash('Фотография не найдена.', 'danger')
        return redirect(url_for('photos'))

    return render_template('photo_detail.html', photo=photo)

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        login = request.form.get('login', '')
        password = request.form.get('pass', '')
        remember = request.form.get('remember') == 'on'

        query = "SELECT id, login, role FROM users WHERE login=%s AND password_hash=SHA2(%s, 256)"
        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (login, password))
            user = cursor.fetchone()

        if user:
            login_user(User(user.id, user.login, user.role), remember=remember)
            flash('Успешная авторизация', category='success')
            return redirect(request.args.get('next', url_for('index')))
        flash('Неправильный логин или пароль.', category='danger')
    
    return render_template('auth.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        confirm_password = request.form.get('password_2')
        
        errors = validate_create_password(password, confirm_password)
        if errors:
            for error in errors.values():
                flash(error, 'danger')
            return render_template('register.html')

        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute('SELECT id FROM users WHERE login=%s', (login,))
            if cursor.fetchone():
                flash('Пользователь с таким логином уже существует.', 'danger')
                return render_template('register.html')

            cursor.execute('INSERT INTO users (login, password_hash) VALUES (%s, SHA2(%s, 256))', (login, password))
            db_connector.connect().commit()

        login_user(User(cursor.lastrowid, login), remember=True)
        flash('Регистрация прошла успешно. Вы вошли в систему.', 'success')
        return redirect(url_for('account'))

    return render_template('register.html')

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/add_photo', methods=['GET', 'POST'])
@login_required
@admin_required
def add_photo():
    if request.method == 'POST':
        title = request.form['title']
        year = request.form['year']
        location = request.form['location']
        description = request.form['description']
        author_name = request.form['author_name']
        image = request.files['image']

        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute("SELECT id FROM authors WHERE name=%s", (author_name,))
            author = cursor.fetchone()

            if not author:
                cursor.execute("INSERT INTO authors (name) VALUES (%s)", (author_name,))
                db_connector.connect().commit()
                author_id = cursor.lastrowid  
            else:
                author_id = author.id

            if image and allowed_file(image.filename):
                image_ext = os.path.splitext(image.filename)[1].lstrip('.').lower()
                image_uuid = str(uuid.uuid4())
                image_filename = secure_filename(image_uuid + '.' + image_ext)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

                cursor.execute('INSERT INTO photos (title, year, location, description, image_uuid, image_ext, author_id) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                               (title, year, location, description, image_uuid, image_ext, author_id))
                db_connector.connect().commit()

                flash('Картина успешно добавлена.', 'success')
                return redirect(url_for('photos'))
            flash('Недопустимый формат файла. Пожалуйста, загрузите изображение в формате jpeg, jpg, png или gif.', 'danger')

    return render_template('add_photo.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из аккаунта.', category='success')
    return redirect(url_for('index'))

@app.route('/perehod')
def black_page():
    return render_template('perehod.html')

@app.route('/edit_photo/<int:photo_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_photo(photo_id):
    if request.method == 'POST':
        title = request.form['title']
        year = request.form['year']
        location = request.form['location']
        description = request.form['description']
        author_id = request.form['author_id']
        image = request.files.get('image')

        try:
            if image and allowed_file(image.filename):
                image_ext = os.path.splitext(image.filename)[1].lstrip('.').lower()
                image_uuid = str(uuid.uuid4())  # Генерируем уникальный ID для изображения
                image_filename = secure_filename(image_uuid + '.' + image_ext)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

                query = '''UPDATE photos SET title=%s, year=%s, location=%s, description=%s, image_uuid=%s, image_ext=%s, author_id=%s WHERE id=%s'''
                params = (title, year, location, description, image_uuid, image_ext, author_id, photo_id)
            else:
                query = '''UPDATE photos SET title=%s, year=%s, location=%s, description=%s, author_id=%s WHERE id=%s'''
                params = (title, year, location, description, author_id, photo_id)

            with db_connector.connect().cursor() as cursor:
                cursor.execute(query, params)
                db_connector.connect().commit()

            flash('Картина успешно обновлена.', 'success')
            return redirect(url_for('photos'))
        except Exception as e:
            flash(f'Ошибка обновления: {str(e)}', 'danger')
            return redirect(url_for('edit_photo', photo_id=photo_id))

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM photos WHERE id=%s', (photo_id,))
        photo = cursor.fetchone()

    if photo is None:
        flash('Фотография не найдена.', 'danger')
        return redirect(url_for('photos'))

    return render_template('edit_photo.html', photo=photo)


@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
@login_required
@admin_required
def delete_photo(photo_id):
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT image_uuid, image_ext FROM photos WHERE id=%s', (photo_id,))
        photo = cursor.fetchone()

        if photo:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f"{photo.image_uuid}.{photo.image_ext}"))
            cursor.execute('DELETE FROM photos WHERE id=%s', (photo_id,))
            db_connector.connect().commit()
            flash('Фотография успешно удалена.', 'success')
        else:
            flash('Фотография не найдена.', 'danger')

    return redirect(url_for('photos'))

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if query:
        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute("SELECT * FROM photos WHERE title LIKE %s", ('%' + query + '%',))
            results = cursor.fetchall()
    else:
        results = []

    return render_template('search_results.html', results=results)

# Ensure allowed file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    app.run(debug=True)
