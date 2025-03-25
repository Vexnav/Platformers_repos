from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateField, FileField, EmailField, BooleanField, IntegerField, RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class VerifyCodeForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify Code')

class ProofOfOwnershipForm(FlaskForm):
    proof = TextAreaField('Proof of Ownership (e.g., detailed description, unique identifiers)',validators=[DataRequired(message="Please provide proof of ownership."), Length(min=10)])
    file = FileField('Upload Proof of Ownership (Optional)',validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx'], 'Allowed file types are JPG, PNG, PDF, DOC, DOCX.')])
    submit = SubmitField('Submit Claim')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Reset Password')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Instructions')

class UserPortalForm(FlaskForm):
    profile_image = FileField('Upload Profile Picture', validators=[DataRequired()])
    bio = TextAreaField('Bio', validators=[DataRequired(message="Please provide some information about yourself.")])
    theme = SelectField('Theme', choices=[('Light', 'Light'), ('Dark', 'Dark')], default='Light')
    notifications = BooleanField('Enable Notifications')
    submit = SubmitField('Update Profile')

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

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email Address',validators=[DataRequired(message="Email is required."),Email(message="Enter a valid email address.")],render_kw={"placeholder": "studentnumber@dut4life.ac.za", "class": "form-control"})
    submit = SubmitField('Send Reset Instructions', render_kw={"class": "btn btn-primary"})

class ReportFoundItemForm(FlaskForm):
    item_name = StringField("Item Name", validators=[DataRequired(), Length(max=100)])
    description = TextAreaField("Description", validators=[DataRequired(), Length(max=500)])
    category_id = SelectField("Category", coerce=int, validators=[DataRequired()])
    location_id = SelectField("Location", coerce=int, validators=[DataRequired()])
    date_found = DateField("Date Found", validators=[DataRequired()])
    image = FileField("Upload Image")
    submit = SubmitField("Report Found Item")


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password',validators=[DataRequired(message="Please enter a new password."),Length(min=8, message="Password must be at least 8 characters long.")])
    confirm_password = PasswordField('Confirm New Password',validators=[DataRequired(message="Please confirm your new password."),EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Reset Password')

class ReviewForm(FlaskForm):
    rating = RadioField('Rating',choices=[('5', '5 Stars'), ('4', '4 Stars'), ('3', '3 Stars'), ('2', '2 Stars'), ('1', '1 Star')],validators=[DataRequired()])
    comment = TextAreaField('Your Review', validators=[DataRequired()])
    submit = SubmitField('Submit Review')