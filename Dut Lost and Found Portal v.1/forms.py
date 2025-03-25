from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateField, FileField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(), EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Register')

class ReportLostItemForm(FlaskForm):
    item_name = StringField("Item Name", validators=[DataRequired(), Length(max=100)])
    description = TextAreaField("Description", validators=[DataRequired(), Length(max=500)])
    category_id = SelectField("Category", coerce=int, validators=[DataRequired()])
    location_id = SelectField("Location", coerce=int, validators=[DataRequired()])
    date_lost = DateField("Date Lost", validators=[DataRequired()])
    image = FileField("Upload Image")
    submit = SubmitField("Report Lost Item")

class ReportFoundItemForm(FlaskForm):
    item_name = StringField("Item Name", validators=[DataRequired(), Length(max=100)])
    description = TextAreaField("Description", validators=[DataRequired(), Length(max=500)])
    category_id = SelectField("Category", coerce=int, validators=[DataRequired()])
    location_id = SelectField("Location", coerce=int, validators=[DataRequired()])
    date_found = DateField("Date Found", validators=[DataRequired()])
    image = FileField("Upload Image")
    submit = SubmitField("Report Found Item")

class ReviewForm(FlaskForm):
    username = StringField("Your Name", validators=[DataRequired(), Length(min=2, max=50)])
    comment = TextAreaField("Your Review", validators=[DataRequired(), Length(max=300)])
    submit = SubmitField("Submit Review")
