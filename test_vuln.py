import sqlite3

def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    conn = sqlite3.connect("db.sqlite")
    return conn.execute(query)

def render_page(user_input):
    return f"<h1>Hello {user_input}</h1>"
