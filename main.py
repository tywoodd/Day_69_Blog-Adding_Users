from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, login_manager
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Base = declarative_base()


##CONFIGURE TABLES

class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author")

    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author = db.relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, ForeignKey('users.id'))

    comment = relationship("Comments", back_populates="post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comments(db.Model, Base):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)

    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, ForeignKey('users.id'))

    post = relationship("BlogPost", back_populates="comment")
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))

    text = db.Column(db.Text, nullable=False)


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


@app.context_processor
def inject_defaults():
    return dict(show_header=not current_user.is_authenticated, comment=current_user.is_authenticated)


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


@app.route('/')
def get_all_posts():
    admin = False
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True
    return render_template("index.html", all_posts=posts, admin=admin)


@app.route('/register', methods=['POST', 'GET'])
def register():
    error = None
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        name = form.name.data

        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            new_user = User(
                email=email,
                password=password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        error = 'Email already registered.'
    return render_template("register.html", form=form, error=error)


@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            error = 'Incorrect email.'

        if existing_user:
            if check_password_hash(pwhash=existing_user.password, password=password):
                login_user(existing_user)
                return redirect(url_for('get_all_posts'))
            error = 'Incorrect password.'

    return render_template("login.html", form=form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    admin = False
    form = CommentForm()
    post = BlogPost.query.filter_by(id=post_id).first()
    if form.validate_on_submit():
        new_comment = Comments(
            text=form.body.data,
            author=current_user,
            post=post
        )
        db.session.add(new_comment)
        db.session.commit()

    requested_post = BlogPost.query.get(post_id)
    comments = Comments.query.all()
    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True
    return render_template("post.html", post=requested_post, admin=admin, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=5000)

# TODO file 7 - #7
#  adding avatars
