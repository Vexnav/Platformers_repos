from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField, DateField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileField, FileAllowed

class LoginForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message="Please enter your username!"), Length(min=2, max=20)])
    password = PasswordField('Password',validators=[DataRequired(message="Please enter your password!")])
    submit = SubmitField('Login')

class ReportLostItemForm(FlaskForm):
    title = StringField('Title',validators=[DataRequired(message="Please enter the lost item title!"), Length(min=2, max=200)])
    description = TextAreaField('Item Description',validators=[DataRequired(message="Please enter item description!")])
    category_id = SelectField('Category',coerce=int,validators=[DataRequired(message="Please select category!")]) 
    date_lost = DateField('Lost Date', format='%Y-%m-%d') 
    image = FileField('Item Image',validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Report Lost Item')

class ReviewForm(FlaskForm):
    name = StringField( 'Your Name', validators=[ DataRequired(message="Please enter your name!"),Length(max=100, message="Name cannot exceed 100 characters.")] )
    review_text = TextAreaField('Your Review', validators=[ DataRequired(message="Review text is required."),Length(min=10, message="Review must be at least 10 characters long.")])
    submit = SubmitField('Submit Review')
