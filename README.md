# Mini-CTF Platform: "FlagQuest V"

This is a full-stack, "vulnerable-by-design" web application built to serve as a Capture The Flag (CTF) game. The project was created to demonstrate practical skills in full-stack development, application security, and my understanding of the **OWASP Top 10** vulnerabilities.

The platform is a complete, gamified system where users can register, log in, hunt for vulnerabilities, and submit flags to earn points. The entire application is styled with a custom "Neon Grid" sci-fi theme.



---

## Features

* **Full User Authentication:** Secure user registration with password hashing (`werkzeug`), login, and session management (`Flask-Login`).
* **Dynamic Challenge Board:** A central dashboard that lists all available challenges.
* **Live Scoring System:** A flag submission endpoint that checks flags against the database, flashes a success/error message, and updates the user's score in real-time.
* **Hint System:** Each challenge features a "Get Hint" button to help players who get stuck.
* **5 Unique Challenges:** A curated set of challenges covering five different classes of vulnerabilities from the OWASP Top 10.
* **Custom Theming:** A futuristic "Neon Grid" theme built with pure CSS, including a grid background, custom fonts (`Orbitron`), and glowing UI elements.

---

## Tech Stack

* **Backend:** **Python**, **Flask**, **Flask-SQLAlchemy**
* **Database:** **SQLite**
* **Authentication:** **Flask-Login** & **Werkzeug.security** for password hashing
* **Frontend:** **HTML**, **CSS**, and **JavaScript** (for hints)
* **Deployment:** `dotenv` for secure secret key management

---

## Installation & Setup

To run this project locally, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/SSabariGirish/mini-ctf-platform.git](https://github.com/SSabariGirish/mini-ctf-platform.git)
    cd mini-ctf-platform
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # Windows
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    
    # Mac/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Create your `.env` file:**
    Create a file named `.env` in the root folder and add your secret key:
    ```
    SECRET_KEY=your_own_super_strong_secret_key
    ```

5.  **Create the database tables:**
    Run the Python interpreter from your **activated venv** and execute the following:
    ```bash
    # On Windows (in Git Bash)
    venv/Scripts/python
    
    # On Mac/Linux
    python
    
    # --- Inside the Python prompt ---
    >>> from app import app, db
    >>> with app.app_context():
    ...     db.create_all()
    ... 
    >>> exit()
    ```

6.  **Register your users:**
    Run the app (`venv/Scripts/python app.py`) and register 2-3 users (e.g., "player1", "player2") so the seeding script has users to work with.

7.  **Seed the database with challenges:**
    Stop the server (Ctrl+C) and run the `seed.py` script. **Make sure to edit `seed.py`** to use the usernames you just registered.
    ```bash
    venv/Scripts/python seed.py
    ```

8.  **Run the app!**
    ```bash
    venv/Scripts/python app.py
    ```
    The app will be live at `http://127.0.0.1:5000`.

---

## The 5 Challenges

This platform includes 5 challenges, each demonstrating a major vulnerability.

### 1. Challenge 1: Reflected XSS
* **Vulnerability:** A search page (`/search`) reflects the user's query back to the page without sanitising it.
* **The Hack:** The user must craft a payload (e.g., `<script>alert(document.cookie)</script>`) to execute JavaScript in their browser and steal the flag from a cookie.

### 2. Challenge 2: SQL Injection
* **Vulnerability:** A fake admin login portal (`/admin-login`) insecurely constructs a raw SQL query using string formatting.
* **The Hack:** The user must use a classic SQLi payload (e.g., `' OR 1=1 --`) in the username field to bypass the password check and gain access to the admin dashboard, where the flag is located.

### 3. Challenge 3: IDOR (Insecure Direct Object Reference)
* **Vulnerability:** The user profile page (`/profile/<id>`) displays a user's profile based on the ID in the URL, but *never checks* if the logged-in user is authorized to see it.
* **The Hack:** The user logs in and visits their own profile (e.g., `/profile/2`). They must then manually change the URL to a "hidden" ID (e.g., `/profile/0`) to view a secret profile and find the flag in the page's HTML source.

### 4. Challenge 4: Security Misconfiguration
* **Vulnerability:** The server exposes a `robots.txt` file that contains a "disallowed" entry for a sensitive backup file.
* **The Hack:** The user must perform reconnaissance by visiting `/robots.txt`, find the path to the backup file (`/static/server_logs.bak`), and navigate to it to read the flag.

### 5. Challenge 5: Insecure File Upload
* **Vulnerability:** A "profile picture" uploader (`/uploader`) fails to properly validate that the uploaded file is an image.
* **The Hack:** The user must upload a non-image file (e.g., a `.txt` file). The backend logic "panics," rejects the file, and flashes an "error" message that conveniently contains the flag.
