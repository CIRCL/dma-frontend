#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-
#

import os.path
import requests, json, pickle
from flask import Flask, render_template, url_for, request, g, redirect
from flask_httpauth import HTTPBasicAuth
from flask.ext.bcrypt import Bcrypt
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import CallbackDict
from urllib.parse import urlparse
from datetime import timedelta
from uuid import uuid4
from redis import Redis
import redis
import re

users = {
    'admin': b'$2b$12$d5zxYbIZWvoVepPWRHnI8uiYbPeJbxDG5ESVrj/APYM/0xAii3PRG',
}

# Allowed extensions to be uploaded
ALLOWED_EXTENSIONS = set(['applet', 'bin', 'dll', 'doc', 'exe', 'html', 'ie', 'jar', 'pdf', 'vbs', 'xls', 'zip', 'jpg', 'jpeg', 'gif', 'png', 'tif', 'tiff', 'apk', 'cmd', 'bat', 'infected'])

# Configurables
BASE_URL = "http://localhost:8090"
TASKS_VIEW = "/tasks/view/"
TASKS_REPORT = "/tasks/report/"
MACHINES_LIST = "/machines/list"

# Setup Flask
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config.from_object(__name__)
app.config['DEBUG'] = True
app.config['DEFAULT_FILE_STORAGE'] = 'filesystem'
app.config['UPLOAD_FOLDER']  = '/home/cuckoo/dma-frontend/web/static/upload'

# Setup HTTP BasicAuth
auth = HTTPBasicAuth()

# Setup bcrypt
bcrypt = Bcrypt(app)

class RedisSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False

class RedisSessionInterface(SessionInterface):
    serializer = pickle
    session_class = RedisSession

    def __init__(self, redis=None, prefix='session:'):
        if redis is None:
            redis = Redis()
        self.redis = redis
        self.prefix = prefix

    def generate_sid(self):
        return str(uuid4())

    def get_redis_expiration_time(self, app, session):
        if session.permanent:
            return app.permanent_session_lifetime
        return timedelta(days=1)

    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = self.generate_sid()
            return self.session_class(sid=sid, new=True)
        val = self.redis.get(self.prefix + sid)
        if val is not None:
            data = self.serializer.loads(val)
            return self.session_class(data, sid=sid)
        return self.session_class(sid=sid, new=True)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        if not session:
            self.redis.delete(self.prefix + session.sid)
            if session.modified:
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain)
            return
        redis_exp = self.get_redis_expiration_time(app, session)
        cookie_exp = self.get_expiration_time(app, session)
        val = self.serializer.dumps(dict(session))
        self.redis.setex(self.prefix + session.sid, val,
                         int(redis_exp.total_seconds()))
        response.set_cookie(app.session_cookie_name, session.sid,
                            expires=cookie_exp, httponly=True,
                            domain=domain)

app.session_interface = RedisSessionInterface()

def status(username, retmax=20):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    t = red.smembers("t:"+username)
    x = []
    at = list(t)
    at = [a for a in at if a != 'null']
    for task in sorted(at, key=lambda x: float(x), reverse=True)[:retmax]:
        r = requests.get(BASE_URL+TASKS_VIEW+task.decode('utf-8'))
        j = json.loads(r.text)
        x.append(j)
    return x

def machines():
    r = requests.get(BASE_URL+MACHINES_LIST)
    return json.loads(r.text)

def checkURL():
    if request.headers.get('X-Forwarded-Host'):
        HOST=request.headers.get('X-Forwarded-Host')
        WEB_PATH=request.headers.get('X-Script-Name')
        PROTO=request.headers.get('X-Scheme')
        URL=PROTO+"://"+HOST+WEB_PATH
    else:
        URI=urlparse(url_for('.index', _external=True))
        HOST=re.split(':', URI[1])[0]
        URL=URI[0]+"://"+URI[1] # http://crgb.circl.lu:5000
    return URL

@auth.verify_password
def verify_pw(username, password):
    if username in users:
        user = username
    else:
        return False
    g.user = user
    return bcrypt.check_password_hash(users[username], password)

@app.route('/dma/')
@app.route('/dma')
def dma():
    if (HOST == "www.circl.lu") or (HOST == "circl.lu"):
        return redirect('/dma/')
    else:
        return redirect('/')

@app.route('/dmabeta/')
@app.route('/dmabeta')
def dmabeta():
    if (HOST == "www.circl.lu") or (HOST == "circl.lu"):
        return redirect('/dmabeta/')
    else:
        return redirect('/')

@app.route('/')
@auth.login_required
def index():
    URL = checkURL()
    s = status(auth.username())
    m = machines()
    return render_template('main.html', auth=auth, s=s, machines=m, urlPath=URL)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
@auth.login_required
def upload():
    URL = checkURL()
    s = status(auth.username())
    m = machines()
    if request.method == 'POST' and request.files['sample'] and request.form['machine'] and request.form['package']:
        f = request.files['sample']
        if f and allowed_file(f.filename):
            sfname = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], sfname))
        r = redis.StrictRedis(host='localhost', port=6379, db=5)
        r.rpush("submit", auth.username()+":"+app.config['UPLOAD_FOLDER']+"/"+request.files['sample'].filename+":"+request.form['machine']+":"+request.form['package'])
    return render_template('main.html', auth=auth, upload=request.files['sample'], s=s, machines=m, urlPath=URL)

@app.route('/rfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def rfetch(taskid, auth=auth):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    t = red.smembers("t:"+auth.username())
    if str(taskid) in str(t):
        r = requests.get(BASE_URL+TASKS_REPORT+str(taskid)+"/html")
        return r.text
    else:
        return "Not allowed"

if __name__ == '__main__':
        app.run(host='0.0.0.0')
