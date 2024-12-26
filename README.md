# Personal Data Vault

## Overview
This project is a secure platform, "Personal Data Vault," that allows users to store and manage sensitive personal data, such as files and documents, with encryption and robust authentication. It is built using Flask, SQLAlchemy, and Bcrypt for security and SQLite for database storage. AES encryption ensures that files are securely stored.



##  Features 

1.  User Registration and Authentication 
   - Secure user registration with password validation.
   - Passwords are hashed using Bcrypt.
   - Login system for user authentication.

2.  Secure File Upload 
   - Users can upload files securely.
   - Uploaded files are encrypted using AES before storage.

3.  File Management Dashboard 
   - A user-friendly interface to view, upload, and manage files.

4.  Data Security 
   - AES encryption in EAX mode to ensure confidentiality and integrity.
   - SQLite database stores encrypted files and hashed passwords securely.

5.  Session Management 
   - Flask sessions to maintain user-specific access.

6.  Validation and Error Handling 
   - Password complexity validation using regex.
   - Comprehensive error handling with database rollbacks.



##  Technologies Used 
-  Flask : Web framework for routing and API creation.
-  SQLAlchemy : Database ORM for managing SQLite.
-  Bcrypt : Password hashing for secure user authentication.
-  AES (Advanced Encryption Standard) : File encryption for data security.
-  HTML/Jinja2 Templates : For rendering the user interface.
-  SQLite : Database for user credentials and file storage.


##  Installation 

1.  Clone the Repository :
      
   git clone <repository-url>
   cd personal-data-vault
    

2.  Set Up Virtual Environment :
      
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
    

3.  Install Dependencies :
      
   pip install -r requirements.txt
    

4.  Run the Application :
      
   python app.py
    
   The application will run at `http://127.0.0.1:5000/`.

5.  Access the Application :
   Open your browser and navigate to `http://127.0.0.1:5000/`.


##  Usage 

1.  Register : Create a new account by providing a username and a strong password.
2.  Login : Access the dashboard using your credentials.
3.  Upload Files : Upload sensitive files that will be encrypted and stored securely.
4.  View Files : Manage and view uploaded files in the dashboard.


##  Project Structure 

project-directory/
|-- app.py                # Main application file
|-- templates/            # HTML templates for the frontend
|   |-- index.html
|   |-- register.html
|   |-- login.html
|   |-- dashboard.html
|-- static/               # Static files (CSS, JS, images)
|-- database.db           # SQLite database file
|-- requirements.txt      # Python dependencies

