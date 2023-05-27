from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import os
import base64
from io import BytesIO
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
app.secret_key = "mysecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.globals['base64'] = base64

db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100))
    role = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Film(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description= db.Column(db.String(255))
    poster = db.Column(db.LargeBinary, nullable=False)
with app.app_context():
    db.create_all()
    db.session.commit()

class FilmForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    poster = FileField('Poster')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    records = Film.query.all()
    return render_template('index.html', records=records)

@app.route('/films')
def films():
    films = Film.query.all()
    return render_template('films.html', films=films)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/films/new', methods=['GET', 'POST'])
@login_required
def new_film():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']   
        poster = request.files['poster']

        # Save the poster image to a temporary file
        filename = secure_filename(poster.filename)
        poster_path = os.path.join(app.root_path, 'static', 'posters', filename)
        poster.save(poster_path)

        # Open the temporary file and resize the image
        img = Image.open(poster_path)
        # Save the image to a BytesIO object
        buffer = BytesIO()
        img.save(buffer, format='JPEG')
        image_bytes = buffer.getvalue()

        # Encode the image bytes as a Base64 string
        image_string = base64.b64encode(image_bytes)
        record = Film(name=name, description=description, poster=image_string)
        db.session.add(record)
        db.session.commit()
        # Delete the temporary file
        os.remove(poster_path)
        flash('Фильм был добавлен!')
        return redirect(url_for('index'))
    return render_template('new_film.html')

@app.route('/film/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_film(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    # Get the film to edit from the database
    film = Film.query.get_or_404(id)
    form = FilmForm(obj=film)
    if request.method == 'POST':
        # Update the film with the new values from the form
        film.name = request.form['name']
        film.description = request.form['description']

        # Check if a new poster image was uploaded
        if request.files['poster'].filename != '':
            print('Uploading new poster image')
            poster = request.files['poster']

            # Save the new poster image to a temporary file
            filename = secure_filename(poster.filename)
            poster_path = os.path.join(app.root_path, 'static', 'posters', filename)
            poster.save(poster_path)

            # Open the temporary file and resize the image
            img = Image.open(poster_path)
            # Save the image to a BytesIO object
            buffer = BytesIO()
            img.save(buffer, format='JPEG')
            image_bytes = buffer.getvalue()

            # Encode the image bytes as a Base64 string
            image_string = base64.b64encode(image_bytes)

            # Update the film's poster with the new image
            film.poster = image_string
            # Delete the temporary file
            if 'poster' in request.files:
                os.remove(poster_path)
            
        else:
            film_bd = Film.query.get_or_404(id)
            film.poster = film_bd.poster

        # Commit the changes to the database
        db.session.commit()

        flash('Фильм был обновлен!')
        return redirect(url_for('films'))

    return render_template('edit_film.html', form=form, film=film)

@app.route('/film/<int:id>/delete', methods=['POST'])
@login_required
def delete_film(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    film = Film.query.get_or_404(id)
    db.session.delete(film)
    db.session.commit()
    flash('Фильм удален')
    return redirect(url_for('films'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('register'))
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Аккаунт создан')
        return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)