from flask import Flask, render_template, request, abort, redirect, make_response
from werkzeug.security import check_password_hash
from Crypto.Cipher import AES
from Crypto.Util import Counter
import json
import os
import struct

app = Flask(__name__)

key = '00000000000000000000000000000000'.decode('hex') # Key was removed

def encrypt(cookie):
  iv = os.urandom(16)
  ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
  cipher = AES.new(key, AES.MODE_CTR, counter = ctr)
  encrypted_cookie = cipher.encrypt(cookie)

  return iv.encode('hex') + encrypted_cookie.encode('hex')

def decrypt(cookie):
  iv = cookie[:32].decode('hex')
  cookie = cookie[32:].decode('hex')
  ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
  cipher = AES.new(key, AES.MODE_CTR, counter = ctr)
  cookie = cipher.decrypt(cookie)

  return cookie

def do_login(user, password, admin):
  resp = make_response(redirect('/'))
  resp.set_cookie('auth', encrypt(json.dumps({'user': user, 'password': password, 'admin': admin})))
  return resp

def load_cookie():
  cookie = {'user': '', 'admin': 0}

  auth = request.cookies.get('auth')
  if auth:
    try:
      cookie = json.loads(decrypt(auth))
    except:
      pass
  return cookie

@app.route('/')
def index():
  cookie = load_cookie()
  return render_template('index.html', user = cookie['user'], admin = cookie['admin'], cookie = cookie)

@app.route('/login', methods=['POST'])
def login():
  user =  request.form.get('user', '')
  password = request.form.get('password', '')

  if user == 'guest': # Accept any passwords for the guest account
    return do_login(user, password, 0)
  if user == 'admin' and check_password_hash('pbkdf2:sha1:1000$bTY1abU0$5503ae46ff1a45b14ff19d5a2ae08acf1d2aacde', password):
    return do_login(user, password, 1)
  return abort(403)

@app.route('/logout', methods=['GET'])
def logout():
  resp = make_response(redirect('/'))
  resp.set_cookie('auth', '', expires=0)
  return resp

@app.route('/admin', methods=['GET'])
def admin():
  cookie = load_cookie()
  if cookie['admin'] == 1:
    return render_template('admin.html', flag='## FLAG ##') # Flag was removed
    
  return abort(403)

if __name__ == '__main__':
  app.run(debug = True)
