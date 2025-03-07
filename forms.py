from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf.file import FileField, FileAllowed

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=200)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ReportItemForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Item Description', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired(), Length(min=2, max=200)])
    status = StringField('Item Type', validators=[DataRequired(), Length(min=4, max=10)])  ('lost' or 'found')
    image = FileField('Item Image', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Report Item')

class MatchItemForm(FlaskForm):
    found_item_id = StringField('Found Item ID', validators=[DataRequired()])
    submit = SubmitField('Match Item')
