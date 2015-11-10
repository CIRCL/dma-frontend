#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#

import os.path
from flask import Flask, render_template, url_for, request, g, redirect
from flask.ext.httpauth import HTTPDigestAuth
from flask.ext.uploads import delete, init, save, Upload
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.storage import get_default_storage_class
from werkzeug.utils import secure_filename
import redis
import requests
import json
users = {
    "admin": "test",
}

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config.from_object(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///home/youruser/tmp/test.db'
app.config['DEFAULT_FILE_STORAGE'] = 'filesystem'
app.config['UPLOADS_FOLDER']  = '/home/youruser/dma/web/static/upload'
app.config['SECRET_KEY'] = 'put your secret key'
init(SQLAlchemy(app), get_default_storage_class(app))
auth = HTTPDigestAuth()


def status(username, retmax=20):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    t = red.smembers("t:"+username)
    x = []
    at = list(t)
    at = [a for a in at if a != 'null']
    for task in sorted(at, key=lambda x: float(x), reverse=True)[:retmax]:
        r = requests.get("http://crg.circl.lu:8090/tasks/view/"+task)
        j = json.loads(r.text)
        x.append(j)
    return x

def machines():
    r = requests.get("http://crg.circl.lu:8090/machines/list")
    return json.loads(r.text)

@auth.get_password
def get_pw(username):
    if username in users:
        return users[username]
    return None

@app.route('/')
@auth.login_required
def index():
    s = status(auth.username)
    m = machines()
    return render_template('main.html', auth=auth, s=s, machines=m)

@app.route('/upload', methods=['GET', 'POST'])
@auth.login_required
def upload():
    s = status(auth.username)
    m = machines()
    if request.method == 'POST' and request.files['sample'] and request.form['machine'] and request.form['package']:
        f = request.files['sample']
        sfname = secure_filename(f.filename)
        f.filename = sfname
        save(f)
        r = redis.StrictRedis(host='localhost', port=6379, db=5)
        r.rpush("submit", auth.username+":"+app.config['UPLOADS_FOLDER']+"/"+request.files['sample'].filename+":"+request.form['machine']+":"+request.form['package'])
    return render_template('main.html', auth=auth, upload=request.files['sample'], s=s, machines=m)

@app.route('/rfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def rfetch(taskid, auth=auth):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    t = red.smembers("t:"+auth.username)
    if str(taskid) in t:
        r = requests.get("http://crg.circl.lu:8090/tasks/report/"+str(taskid)+"/html")
        return r.text
    else:
        return "Not allowed"
if __name__ == '__main__':
        app.run(debug=False, host='0.0.0.0')

