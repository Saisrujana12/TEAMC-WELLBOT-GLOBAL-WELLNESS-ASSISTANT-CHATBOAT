from flask_sqlalchemy import SQLAlchemy

# Initialize the database object
db = SQLAlchemy()

# Define the User model
class User(db.Model):
    """
    User Model for storing user details
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Stores hashed password
    language = db.Column(db.String(20), default='English') # Added for Milestone 1 Requirement

    def __repr__(self):
        return f'<User {self.name}>'
