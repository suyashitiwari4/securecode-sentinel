import hashlib
import sqlite3
import subprocess

import yaml

# 1. Hardcoded secret (fake, random-looking value)
api_key = "a8f3k29dj4h5g6s7d8f9a0b1c2d3e4f5"
db_password = "Xk9#mP2$vL8@qR4!"


# 2. SQL injection: query built with string concatenation
def get_user(name):
    conn = sqlite3.connect("db.sqlite")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()


# 3. Unsafe eval on user input
def calculate(expression):
    return eval(expression)


# 4. Command injection risk: shell=True with user input
def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True)


# 5. Weak hash for passwords
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# 6. Unsafe YAML loading
def load_config(text):
    return yaml.load(text)