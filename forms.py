from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo


class RegistrationForm(FlaskForm):
    username = StringField('Username', id='uname', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', id='pword', validators=[DataRequired(), Length(min=1, max=20)])
    phone_number = StringField('Phone Number', id='2fa', validators= [Length(max=11)])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    username = StringField('Username', id='uname', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', id='pword', validators=[DataRequired(), Length(min=1, max=20)])
    phone_number = StringField('2fa', id='2fa', validators= [Length(max=11)])
    submit = SubmitField('Login')


class SpellCheckForm(FlaskForm):
    checktext = StringField('Input Text', id='inputtext', validators=[DataRequired()])
    submit = SubmitField('Submit')

class HistoryForm(FlaskForm):
    username = StringField('User Search', id='uname', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginHistoryForm(FlaskForm):
    username = StringField('User Search', id='uname', validators=[DataRequired()])
    submit = SubmitField('Submit')