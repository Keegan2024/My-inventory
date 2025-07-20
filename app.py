from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Add more routes as needed
# @app.route('/submit_report') etc.

if __name__ == '__main__':
    app.run(debug=True)
