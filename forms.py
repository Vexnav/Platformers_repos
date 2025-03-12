from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField, DateField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileField, FileAllowed

class LoginForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message="Please enter your username!"), Length(min=2, max=20)])
    password = PasswordField('Password',validators=[DataRequired(message="Please enter your password!")])
    submit = SubmitField('Login')

class ReportLostItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(max=100, message="Item name cannot exceed 100 characters.")])
    category = SelectField('Category',validators=[DataRequired()])
    last_seen_location = StringField('Last Seen Location', validators=[DataRequired(), Length(max=255, message="Location cannot exceed 255 characters.")])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500, message="Description cannot exceed 500 characters.")])
    date_lost = DateField('Date Found', validators=[DataRequired()], format='%Y-%m-%d')
    image = FileField('Upload Image', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Submit')

class ReportFoundItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(max=100, message="Item name cannot exceed 100 characters.")])
    category = SelectField('Category',validators=[DataRequired()])
    location_found = StringField('Location Found', validators=[DataRequired(), Length(max=255, message="Location cannot exceed 255 characters.")])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500, message="Description cannot exceed 500 characters.")])
    date_found = DateField('Date Found', validators=[DataRequired()], format='%Y-%m-%d')
    image = FileField('Upload Image', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Submit')


