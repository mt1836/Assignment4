from datetime import datetime
import subprocess, bcrypt
from flask import Flask, render_template, url_for, flash, redirect, session, g, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, current_user, logout_user, login_required
from forms import RegistrationForm, LoginForm, SpellCheckForm, HistoryForm, LoginHistoryForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
search_user = -1

#app.config['WTF_CSRF_ENABLED'] = False

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    phone = db.Column(db.String(11))
    password = db.Column(db.String(60), nullable=False)
    salt = db.Column(db.String(), nullable=False)
    post = db.relationship('Post', backref='user', lazy=True)
    login_history = db.relationship('Login_history', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.password}', '{self.phone}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    spell_submitted = db.Column(db.Text, nullable=False)
    spell_results = db.Column(db.Text)
    numqueries = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.id}', '{self.user_id}', '{self.spell_submitted}', '{self.spell_results}', '{self.date_posted}', '{self.numqueries}')"


class Login_history(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout_timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Login_history('{self.user_id}', '{self.login_timestamp}', '{self.logout_timestamp}')"
        

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def setup_db():
    db.drop_all()
    db.create_all()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(('Administrator@1').encode('utf-8'),salt)
    user = User(username='admin', password=hashed, phone='12345678901', salt=salt)
    db.session.add(user)
    db.session.commit()

@app.route("/")

@app.route("/register", methods=['GET', 'POST'])
def register():
    logout()
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user == None:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
                user = User(username=form.username.data, password=hashed, phone=form.phone_number.data, salt=salt)
                db.session.add(user)
                db.session.commit()
                regstatus = 'Success you have been successfully registered!'
                return render_template('register.html', title='Register', form=form, regstatus=regstatus)
            else:
                regstatus = 'Username already exists!'
                return render_template('register.html', title='Register', form=form, regstatus=regstatus)
        else:
            regstatus = 'Failure to register.  Please complete the required fields appropriately'
            return render_template('register.html', title='Register', form=form, regstatus=regstatus)
    else:
        return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    logout()
    form = LoginForm()
    user = User.query.filter_by(username=form.username.data).first()
    if user == None:
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
    elif form.validate_on_submit():
        hashed_login = bcrypt.hashpw((form.password.data).encode('utf-8'),user.salt)
        if user == None:
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.username.data == user.username and hashed_login == user.password and form.phone_number.data == user.phone:
            login_user(user)
            login_time = Login_history(user=current_user, login_timestamp=datetime.now())
            db.session.add(login_time)
            db.session.commit()
            result = 'success'
            return render_template('login.html', title='Login', form=form, result=result)
        elif hashed_login != user.password or form.username.data != user.username:
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.phone_number.data != user.phone:
            result = 'Two-factor failure'
            return render_template('login.html', title='Login', form=form, result=result)
    else:
        return render_template('login.html', title='Login', form=form)


@app.route("/logout", methods=['GET'])
@login_required
def logout():
    if current_user != None:
        loginhistory = current_user.login_history
        loginhistory[-1].logout_timestamp = datetime.now()
        db.session.commit()
    logout_user()
    return redirect(url_for('login'))
    

@app.route("/spell_check", methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellCheckForm()
    global input_text
    global spellcheck_results
    if form.validate_on_submit():
        input_text = form.checktext.data
        input_file = open("spellcheckfile.txt","w")
        input_file.write(input_text)
        input_file.close()
        spellcheck_results = subprocess.check_output(["./a.out", "spellcheckfile.txt", "wordlist.txt"])
        spellcheck_results = spellcheck_results.decode('utf-8')
        spellcheck_results = spellcheck_results.replace("\n",", ")
        spellcheck_results = spellcheck_results.rstrip(", ")
        spellcheck_file = open("resultsfile.txt","w")
        spell_check = Post(spell_submitted=input_text, spell_results=spellcheck_results, user=current_user, date_posted=datetime.now())
        db.session.add(spell_check)
        db.session.commit()
        spellcheck_file.write(spellcheck_results)
        spellcheck_file.close()
        return render_template('spell_check.html', title='Spell Checker Results', form=form, spellcheck_results=spell_check.spell_results, input_text=spell_check.spell_submitted)
    else:
        return render_template('spell_check.html', title='Spell Checker', form=form)


@app.route("/history", 
methods=['GET', 'POST'])
@login_required
def history():
    form = HistoryForm()
    cuser = current_user.username
    global search_user
    if cuser == None:
        return render_template('error.html', title='ERROR')
    if cuser == 'admin':
        if form.validate_on_submit():
            search_user = form.username.data
            user = User.query.filter_by(username=search_user).first()
            numqueries = len(user.post)
            queries = user.post 
            return render_template('history.html', title='History', form=form, user=user, numqueries=numqueries, cuser=cuser, queries=queries, search_user=search_user)
        else:
            return render_template('history.html', title='History', form=form, cuser=cuser)
    else:
        user = User.query.filter_by(username=current_user.username).first()
        numqueries = len(user.post)
        queries = user.post
        return render_template('history.html', title='History', form=form, user=user, numqueries=numqueries, cuser=cuser, queries=queries)
        

@app.route("/history/query<int:queryid>")
@login_required
def history_query(queryid):
    cuser = current_user.username
    global search_user
    query_id = queryid
    manquery_username = Post.query.filter_by(id=query_id).first().user.username
    manquery_submitted = Post.query.filter_by(id=query_id).first().spell_submitted
    manquery_results = Post.query.filter_by(id=query_id).first().spell_results
    if cuser != manquery_username and cuser == 'admin' and search_user == -1:
        return render_template('query_details.html', title='Query Details', search_user=search_user, cuser=cuser, query_id=query_id, manquery_username=manquery_username, manquery_submitted=manquery_submitted, manquery_results=manquery_results)
    elif cuser != manquery_username and cuser != 'admin' and search_user == -1:
        return render_template('error.html', title='ERROR')
    elif cuser == manquery_username and cuser == 'admin' and search_user == -1:
        return render_template('query_details.html', title='Query Details', search_user=search_user, cuser=cuser, query_id=query_id, manquery_username=manquery_username, manquery_submitted=manquery_submitted, manquery_results=manquery_results)
    elif cuser == manquery_username and cuser != 'admin' and search_user == -1:
        return render_template('query_details.html', title='Query Details', search_user=search_user, cuser=cuser, query_id=query_id, manquery_username=manquery_username, manquery_submitted=manquery_submitted, manquery_results=manquery_results)
    elif cuser == 'admin':    
        username = search_user
        user = User.query.filter_by(username=search_user).first()
        numqueries = len(user.post)
        for i in range(numqueries):
            if user.post[i].id == query_id:
                query_submitted = user.post[i].spell_submitted
                query_results = user.post[i].spell_results
        return render_template('query_details.html', title='Query Details', username=username, cuser=cuser, query_id=query_id, query_submitted=query_submitted, query_results=query_results)
    else:
        username = cuser
        user = User.query.filter_by(username=cuser).first()
        numqueries = len(user.post)
        for i in range(numqueries):
            if user.post[i].id == query_id:
                query_submitted = user.post[i].spell_submitted
                query_results = user.post[i].spell_results
        return render_template('query_details.html', title='Query Details', username=username, cuser=cuser, query_id=query_id, query_submitted=query_submitted, query_results=query_results)


@app.route("/history/login_history", methods=['GET', 'POST'])
@login_required
def login_history():
    form = LoginHistoryForm()
    cuser = current_user.username
    user = None
    global login_search_user
    if cuser == None:
        return render_template('error.html', title='ERROR')
    elif cuser == 'admin':
        if form.validate_on_submit():
            login_search_user = form.username.data
            user = User.query.filter_by(username=login_search_user).first()
            numqueries = len(user.post)
            loginhistory = user.login_history
            loginhistorylen = len(loginhistory)
            loginlogstime = loginhistory[0].login_timestamp
            logoutlogstime = loginhistory[0].logout_timestamp   
            return render_template('login_history.html', title='History', form=form, user=user, loginlogstime = loginlogstime, logoutlogstime=logoutlogstime, loginhistory=loginhistory, cuser=cuser, login_search_user=login_search_user)
        else:
            return render_template('login_history.html', title='History', form=form, cuser=cuser)
    else:
        return render_template('error.html', title='ERROR')

setup_db()
if __name__ == '__main__':
    app.run(debug=True)
    
