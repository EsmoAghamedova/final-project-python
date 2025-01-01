from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'Esmo2009'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cognipeak.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'  # Folder for lesson images
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

# Model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    videos_watched = db.Column(db.Integer, default=0)
    points = db.Column(db.Integer, default=0)


    def __repr__(self):
        return f'<User {self.username}>'
    
class VideoWatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)  # Reference to the Lesson
    watched_at = db.Column(db.DateTime, default=datetime.utcnow)  # Store the watch time

# Model for Subject
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(10), nullable=False)
    lessons = db.relationship('Lesson', backref='subject', lazy=True)  # სწორად განსაზღვრული ურთიერთობა

    __table_args__ = (
        db.UniqueConstraint('name', 'class_name', name='_name_class_uc'),
    )

    def __repr__(self):
        return f'<Subject {self.name} {self.class_name}>'

# Model for Lesson (with image and title)
class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url= db.Column(db.String(200), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)  # სწორი ForeignKey

    def __repr__(self):
        return f'<Lesson {self.title} for Subject {self.subject.name}>'
    
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Initialize database tables
@app.before_request
def create_tables():
    db.create_all()
    

    
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard' if not session.get('is_admin') else 'admin_panel'))
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        new_message = ContactMessage(name=name, email=email, message=message)
        db.session.add(new_message)
        db.session.commit()

        print(f"New message from {name} ({email}): {message}")  
        flash("შეტყობინება წარმატებით გაიგზავნა!", 'success')

    return render_template('contact.html')

@app.route('/gakvetilebi')
def gakvetilebi():
    return render_template('1.html')

# Password validation function
def validate_password(password):
    if len(password) < 8:
        return False, "პაროლი 8 ან მეტ ასოს უნდა შეიცავდეს."
    
    if not re.search("[A-Z]", password):  # Check for at least one uppercase letter
        return False, "პაროლი ერთ დიდ ლათინურ ასოს მაინც უნდა შეიცავდეს."
    
    if not re.search("[a-z]", password):  # Check for at least one lowercase letter
        return False, "პაროლი ერთ პატარა ლათინურ ასოს მაინც უნდა შეიცავდეს."
    
    if not re.search("[0-9]", password):  # Check for at least one digit
        return False, "პაროლი ერთ ციფრს მაინც უნდა შეიცავდეს."
    
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):  # Check for special characters
        return False, "პაროლი ერთ სპეციალურ სიმბოლოს მაინც უნდა შეიცავდეს."
    
    return True, "Password is valid."

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not all([name, username, email, password, confirm_password]):
            flash("ყველა უჯრა შეავსეთ!", 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("პაროლი არ ემთხვევა!", 'error')
            return redirect(url_for('signup'))

        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('signup'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("იგივე მეილით ან მომხმარებლის სახელით მომხმარებელი არსებობს!", 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(name=name, username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("წარმატებით დარეგისტრირდით!", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash("პრობლემა შეიქმნა, ხელახლა სცადეთ მოგვიანებით.", 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form.get('email_or_username', '').strip()
        password = request.form.get('password', '').strip()

        if not email_or_username or not password:
            flash("შეიყვანეთ ყველა უჯრა!", 'error')
            return redirect(url_for('login'))

        # Find user by email or username
        user = User.query.filter(
            (User.email == email_or_username) | (User.username == email_or_username)
        ).first()

        if user:
            print(f"User found: {user.username}, {user.email}")  # Log

            # If password matches
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['is_admin'] = user.email == "esmira.agamedovate03@geolab.edu.ge"
                flash("წარმატებით შეხვდით!", 'success')

                # Redirect to admin panel if email matches
                return redirect(url_for('admin_panel' if user.email == "esmira.agamedovate03@geolab.edu.ge" else 'dashboard'))
            else:
                print("Incorrect password!")  # Log
                flash("პაროლი არასწორია!", 'error')
        else:
            print("User not found!")  # Log
            flash("მონაცემი არასწორია!", 'error')

        return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    # შეამოწმე, არის თუ არა მომხმარებელი ავტორიზებული და არა ადმინისტრატორი
    if 'user_id' in session and not session.get('is_admin'):
        # მომხმარებლის მონაცემების აღება
        user = User.query.get(session['user_id'])
        if not user:
            flash("მომხმარებელი ვერ მოიძებნა!", 'error')
            return redirect(url_for('login'))

        # ვიდეოს ქულის გამოთვლა
        video_score = user.videos_watched * 50

        # წარმატების შეტყობინების დამატება
        flash(f"გამარჯობა {user.name}!", 'success')

        # Dashboard შაბლონის რენდერინგი
        return render_template(
            'dashboard.html',
            user_name=user.name,
            videos_watched=user.videos_watched,
            total_score=video_score
        )

    # არავაუთორიზებულ მომხმარებელს გადამისამართება
    flash("You need to log in first!", 'error')
    return redirect(url_for('login'))

@app.route('/foryou')
def foryou():
    # Query all lessons to display on the 'for you' page
    lessons = Subject.query.all()
    return render_template('foryou.html', subjects=lessons)

@app.route('/watch/<int:lesson_id>')
def watch_video(lesson_id):
    # შეამოწმეთ, არის თუ არა მომხმარებელი შესული
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        
        # მოძებნეთ გაკვეთილი ID-ის მიხედვით
        lesson = Lesson.query.get(lesson_id)
        
        if user and lesson:
            # შეამოწმეთ, თუ ეს ვიდეო უკვე ნანახია
            video_watch = VideoWatch.query.filter_by(user_id=user.id, lesson_id=lesson.id).first()
            
            if not video_watch:  # თუ ვიდეო ჯერ არ ნანახია
                # დაამატეთ ნაყურები ვიდეო და ქულა
                user.videos_watched += 1
                user.points += 50
                
                # დაამატეთ ახალი ჩანაწერი VideoWatch მოდელში
                video_watch = VideoWatch(user_id=user.id, lesson_id=lesson.id)
                db.session.add(video_watch)
                db.session.commit()
                
                flash(f"გილოცავთ! გაკვეთილი '{lesson.title}' ნაყურებ ვიდეოებში დაემატა.", 'success')
            else:
                flash(f"თქვენ უკვე ნახეთ ვიდეო '{lesson.title}'.", 'info')
            
            # ლინკზე გადართვა, რომ გაკვეთილის ვიდეო გადაიწეროს
            return redirect(lesson.url)  # გადამისამართება გაკვეთილის URL-ზე
        else:
            flash("მომხმარებელი ან გაკვეთილი ვერ მოიძებნა.", 'error')
            return redirect(url_for('dashboard'))
    else:
        flash("ავტორიზაცია საჭიროა!", 'error')
        return redirect(url_for('login'))

@app.route('/search_lessons', methods=['GET'])
def search_lessons():
    query = request.args.get('query')  # Receive 'query' parameter
    lessons = Lesson.query.filter(
        Lesson.title.contains(query)  # Search for lessons with a title that contains the query
    ).all()  # Retrieve matching lessons from the database
    return render_template('search_results.html', lessons=lessons)  # Display the found lessons

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:  # თუ მომხმარებელი არსებობს
            if request.method == 'POST':
                # ახალი მონაცემები
                new_name = request.form['name']
                new_username = request.form['username']
                new_email = request.form['email']

                # შეამოწმე, თუ უკვე არსებობს იგივე მომხმარებლის სახელი ან მეილი
                existing_user = User.query.filter_by(username=new_username).first()
                existing_email = User.query.filter_by(email=new_email).first()

                # თუ მომხმარებლის სახელი ან მეილი არსებობს
                if existing_user and existing_user.id != user.id:
                    flash("ეს მომხმარებლის სახელი უკვე დაკავებულია.", 'error')
                elif existing_email and existing_email.id != user.id:
                    flash("ეს მეილი უკვე დაკავებულია.", 'error')
                else:
                    # განახლება
                    user.name = new_name
                    user.username = new_username
                    user.email = new_email
                    db.session.commit()  # შენახვა
                    flash("მომხმარებლის მონაცემები წარმატებით განახლდა.", 'success')
                    return redirect(url_for('profile'))  # გადამისამართება ისევ პროფილის გვერდზე

            return render_template('profile.html', user=user)  # ნაჩვენები პროფილის გვერდი
        else:
            flash("მომხმარებელი ვერ მოიძებნა.", 'error')
            return redirect(url_for('login'))  # თუ მომხმარებელი ვერ მოიძებნა, გადმოხვედით სარეგისტრაციო გვერდზე
    else:
        flash("ავტორიზაცია საჭიროა!", 'error')
        return redirect(url_for('login'))  # თუ არ არის ავტორიზებული, გადმოიყვანე შესვლის გვერდზე

@app.route('/settings')
def settings():
    return render_template('setting.html')

@app.route('/reset_progress', methods=['POST'])
def reset_progress():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        
        if user:
            # ნაყურები ვიდეოებისგან განახლება
            user.videos_watched = 0
            
            # ქულებისგან განახლება
            user.points = 0
            
            # ყველა ნანახი ვიდეოს ამოღება VideoWatch მოდელიდან
            VideoWatch.query.filter_by(user_id=user.id).delete()
            
            db.session.commit()  # ცვლილებების შენახვა
            
            flash("თქვენი პროგრესი წარმატებით განულდა.", 'success')
            return redirect(url_for('dashboard'))  # გადამისამართება მთავარ გვერდზე
        else:
            flash("მომხმარებელი ვერ მოიძებნა.", 'error')
            return redirect(url_for('dashboard'))
    else:
        flash("ავტორიზაცია საჭიროა!", 'error')
        return redirect(url_for('login'))
    
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            if request.method == 'POST':
                old_password = request.form['old_password']
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']

                # მოძებნე, რომ ძველი პაროლი სწორია
                if not check_password_hash(user.password, old_password):
                    flash("თქვენი ძველი პაროლი არასწორია.", 'error')
                    return redirect(url_for('change_password'))

                # შეამოწმე ახალი პაროლის სიძლიერე
                if new_password != confirm_password:
                    flash("ახალი პაროლები არ ემთხვევა.", 'error')
                    return redirect(url_for('change_password'))

                # პაროლის განახლება
                user.password = generate_password_hash(new_password)
                db.session.commit()  # შენახვა

                flash("პაროლი წარმატებით შეიცვალა.", 'success')
                return redirect(url_for('dashboard'))  # გადამისამართება მთავარ გვერდზე
        else:
            flash("მომხმარებელი ვერ მოიძებნა.", 'error')
            return redirect(url_for('login'))
    else:
        flash("ავტორიზაცია საჭიროა!", 'error')
        return redirect(url_for('login'))
    
@app.route('/check_old_password', methods=['POST'])
def check_old_password():
    data = request.get_json()
    old_password = data.get('old_password')

    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user and check_password_hash(user.password, old_password):
            return jsonify({'success': True})
        else:
            return jsonify({'success': False}), 400
    return jsonify({'success': False}), 400

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            # წაშლა დაკავშირებული მონაცემებისგან (მაგალითად, ვიდეო ნახვები და ქულები)
            # აქ შეგიძლიათ დაამატოთ სხვა დაკავშირებული ჩანაწერები, რომლებიც უნდა წაიშალოს
            VideoWatch.query.filter_by(user_id=user.id).delete()  # ვიდეოების ნახვების წაშლა
            db.session.commit()

            # მომხმარებლის წაშლა
            db.session.delete(user)
            db.session.commit()

            # მომხმარებელი გასულა სესიიდან
            session.pop('user_id', None)

            flash("თქვენი პროფილი წარმატებით წაიშალა.", 'success')
            return redirect(url_for('index'))  # გადამისამართება მთავარ გვერდზე
        else:
            flash("მომხმარებელი ვერ მოიძებნა.", 'error')
            return redirect(url_for('dashboard'))
    else:
        flash("ავტორიზაცია საჭიროა!", 'error')
        return redirect(url_for('login'))

@app.route('/contactt')
def contactt():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        new_message = ContactMessage(name=name, email=email, message=message)
        db.session.add(new_message)
        db.session.commit()

        print(f"New message from {name} ({email}): {message}")  
        flash("შეტყობინება წარმატებით გაიგზავნა!", 'success')

    return render_template('contact-1.html')

# Admin panel routes
@app.route('/admin-sagani', methods=['GET', 'POST'])
def admin_panel():
    if 'user_id' in session and session.get('is_admin'):
        if request.method == 'POST':
            subject_name = request.form.get('subject_name', '').strip()
            class_name = request.form.get('class_name', '').strip()

            if subject_name and class_name:
                try:
                    # Check if subject already exists with same name and class
                    existing_combination = Subject.query.filter_by(name=subject_name, class_name=class_name).first()

                    if existing_combination:
                        flash(f"Subject '{subject_name}' and Class '{class_name}' already exists!", 'error')
                    else:
                        new_subject = Subject(name=subject_name, class_name=class_name)
                        db.session.add(new_subject)
                        db.session.commit()
                        flash(f"Subject '{subject_name}' and Class '{class_name}' added successfully!", 'success')
                
                except Exception as e:
                    db.session.rollback()
                    flash(f"An error occurred while adding the subject: {e}", 'error')
            else:
                flash("Both Subject name and Class name are required!", 'error')

        subjects = Subject.query.all()

        return render_template('admin-sagani.html', subjects=subjects)
    
    flash("You need to log in as an admin!", 'error')
    return redirect(url_for('login'))

# Edit Subject route
@app.route('/admin/sagani/edit/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    if 'user_id' in session and session.get('is_admin'):
        subject = Subject.query.get(subject_id)
        if request.method == 'POST':
            subject_name = request.form.get('subject_name', '').strip()
            class_name = request.form.get('class_name', '').strip()

            if subject_name and class_name:
                existing_combination = Subject.query.filter_by(name=subject_name, class_name=class_name).first()

                if existing_combination and existing_combination.id != subject_id:
                    flash(f"Subject '{subject_name}' and Class '{class_name}' already exists!", 'error')
                else:
                    subject.name = subject_name
                    subject.class_name = class_name
                    try:
                        db.session.commit()
                        flash(f"Subject '{subject_name}' updated successfully!", 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f"An error occurred while updating the subject: {e}", 'error')
            else:
                flash("Both Subject name and Class name are required!", 'error')

        return render_template('edit_subject.html', subject=subject)
    flash("You need to log in as an admin!", 'error')
    return redirect(url_for('login'))

# Delete Subject route
@app.route('/admin/sagani/delete/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if 'user_id' in session and session.get('is_admin'):
        subject = Subject.query.get(subject_id)
        try:
            db.session.delete(subject)
            db.session.commit()
            flash(f"Subject '{subject.name}' deleted successfully!", 'success')
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during deletion, please try again later.", 'error')

        return redirect(url_for('admin_panel'))
    flash("You need to log in as an admin!", 'error')
    return redirect(url_for('login'))

@app.route('/subject-page/<int:subject_id>', methods=['GET'])
def subject_page(subject_id):
    subject = Subject.query.get(subject_id)  # Assuming Subject is a model for the subject
    lessons = Lesson.query.filter_by(subject_id=subject_id).all()  # Fetch lessons for the specific subject
    return render_template('subject_page.html', subject=subject, lessons=lessons)

@app.route('/admin-video', methods=['GET', 'POST'])
def admin_video():
    if request.method == 'POST':
        title = request.form['lesson-title']
        subject_id = request.form['subject_id']
        
        # უბრალოდ დაამატეთ გაკვეთილი, სადაც სურათის დასამატებლად არ ხდება მოქმედება
        lesson = Lesson(title=title, url=request.form['lesson-url'], subject_id=subject_id)
        db.session.add(lesson)
        db.session.commit()
        
        return redirect(url_for('admin_video'))
    
    subjects = Subject.query.all()
    lessons = Lesson.query.all()
    return render_template('admin-video.html', subjects=subjects, lessons=lessons)

@app.route('/edit_lesson/<int:lesson_id>', methods=['GET', 'POST'])
def edit_lesson(lesson_id):
    lesson = Lesson.query.get(lesson_id)  # Get the lesson by id
    subjects = Subject.query.all()  # Get all subjects for the dropdown

    if request.method == 'POST':
        lesson.title = request.form['lesson-title']
        lesson.subject_id = request.form['subject_id']
        lesson.url = request.form['lesson-url']

        db.session.commit()
        flash('გაკვეთილი განახლებულია!', 'success')
        return redirect(url_for('admin_video'))

    return render_template('edit-lesson.html', lesson=lesson, subjects=subjects)

@app.route('/delete_lesson/<int:lesson_id>', methods=['POST'])
def delete_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    db.session.delete(lesson)
    db.session.commit()
    flash('გაკვეთილი წაშლილია!')
    return redirect(url_for('admin_video'))

@app.route('/admin-comments')
def admin_comments():
    messages = ContactMessage.query.all()
    return render_template('comments.html', messages=messages)


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", 'success')
    return redirect(url_for('index'))  # ამან უნდა განახორციელოს გადამისამართება

# Run app
if __name__ == '__main__':
    app.run(debug=True)
