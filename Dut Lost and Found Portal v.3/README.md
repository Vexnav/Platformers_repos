DUT Lost & Found Portal A web application for managing lost and found items at Durban University of Technology (DUT).

Features User Authentication: Register, login, and manage user profiles

Item Reporting: Report lost or found items with details and images

Matching System: Automatically matches lost and found items based on criteria

Admin Dashboard: Manage items, categories, locations, and view statistics

Email Notifications: Confirmations, password resets, and claim notifications

Data Visualization: Charts and graphs for statistical analysis

Responsive Design: Works on desktop and mobile devices

Installation Clone the repository:

cd dut-lost-found Create and activate a virtual environment:

bash python -m venv venv source venv/bin/activate # On Windows use venv\Scripts\activate Install dependencies:

bash pip install -r requirements.txt Set up environment variables:

Create a .env file based on .env.example

Fill in required configuration values (database URI, email settings, etc.)

Initialize the database:

bash flask db init flask db migrate flask db upgrade Run the application:

bash python app.py Configuration The application requires the following configuration (set in .env or environment variables):

SECRET_KEY: Flask secret key

SQLALCHEMY_DATABASE_URI: Database connection string

MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD: Email server configuration

UPLOAD_FOLDER: Path for storing uploaded images

Default Admin Account A default admin account is created automatically:

Username: DUTAdmin

Password: $$Dut050504

API Endpoints /api/stats: Returns JSON statistics about items reported and matched

Technologies Used Python 3

Flask

SQLAlchemy (PostgreSQL/SQLite)

Flask-Login

Flask-Mail

Flask-Migrate

Bootstrap 5

Chart.js

Contributing Contributions are welcome! Please fork the repository and submit a pull request.

License This project is licensed under the MIT License.
