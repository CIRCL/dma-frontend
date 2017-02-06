#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

import os.path, sys, time, random, pprint
from pathlib import Path
import requests, json, pickle
import hashlib
from flask import Flask, Response, render_template, url_for, request, g, redirect
from flask_httpauth import HTTPBasicAuth
from flask_bcrypt import Bcrypt
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import CallbackDict
from urllib.parse import urlparse
from datetime import timedelta, datetime
from uuid import uuid4
import redis
from redis import Redis
import smtplib
from email.mime.text import MIMEText
import re

# check for xkcd module, used in maintenance mode
try:
    import xkcd
    XKCD = True
except ImportError:
    print("Disabling XKCD support, some unicorns are crying right now, some where :'(")
    XKCD = False

# check for DMAusers file, needed to login and auth analyses
try:
    from DMAusers import *
except ImportError:
    sys.exit("Please create a file with a users dictionary in: DMAusers.py")

# check if redis is running
try:
    rs = Redis("localhost")
    response = rs.client_list()
except redis.ConnectionError:
    sys.exit("Redis Connection Error? Is redis-server running?")

# this is bad style etc, but a dirty fix for now
# checking if run from main web app directory
try:
    goodPath = os.path.getmtime('static/img/online_communities.png')
except:
    sys.exit("You have to start index.py IN the web directory.")

# Configurables
from DMAconfig import *

from flask_debugtoolbar import DebugToolbarExtension

# Setup Flask
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config.from_object(__name__)
app.config['SECRET_KEY'] = 'Replace WITH your $ecret K3y!'
app.config['PREFERRED_URL_SCHEME'] = 'http'

# If DEBUG mode is on, make sure we see all the necessary outputs
if DEBUG:
    app.config['DEBUG'] = True
    toolbar = DebugToolbarExtension(app)
    # Disable GET log, also disable Debug Log
    import logging
    log = logging.getLogger('werkzeug')
    log.disabled = False
    pp = pprint.PrettyPrinter(indent=4)
    flaskAppConfig = app.config
    pp.pprint(flaskAppConfig)
else:
    app.config['DEBUG'] = False

app.config['DEFAULT_FILE_STORAGE'] = 'filesystem'

### /!\ Configure upload folder /!\
app.config['UPLOAD_FOLDER']  = UPLOAD_FOLDER

try:
    file_or_directory = Path(app.config['UPLOAD_FOLDER'])
    if not file_or_directory.exists():
        raise
except:
    sys.exit("Please create the upload folder: {}".format(app.config['UPLOAD_FOLDER']))

# Setup HTTP BasicAuth
auth = HTTPBasicAuth()

# Setup bcrypt
bcrypt = Bcrypt(app)

# import redis scaffolding
from redisLocal import *

# instantiate a redis session interface in flask app
app.session_interface = RedisSessionInterface()

def getTime(seconds):
    sec = timedelta(seconds=int(seconds))
    d = datetime(1,1,1) + sec

    if d.day-1 > 0:
        return("{} day(s), {} hour(s), {} minute(s) and {} seconds".format(d.day-1, d.hour, d.minute, d.second))
    elif d.hour > 0:
        return("{} hour(s), {} minute(s) and {} seconds".format(d.hour, d.minute, d.second))
    elif d.minute > 0:
        return("{} minute(s) and {} seconds".format(d.minute, d.second))
    else:
        return("{} seconds".format(d.second))

def grabTask(username, flavour="v1"):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    k = red.keys()
    t = checkFlavour(flavour, red)
    return t

def statusDevel(username, retmax=20, flavour="v1"):
    tasks = {}
    x = []

    if retmax == 'all':
        retmax = -1
    else:
        retmax = int(retmax)

    # Connect to redis db 5
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    # read in all the keys
    k = red.keys()
    if len(k) >= 1:
        for ke in k:
            key = ke.decode('utf-8')
            keySplit = key.split(":")
            if key.count(":") == 2:
                flavour = keySplit[2]
                if DEBUG: print("Grabbing client {} flavour {}".format(keySplit[1], flavour))
                t = grabTask(username, flavour)
                #x.append(fetchTask(t, retmax))
                x = fetchTask(t, retmax)
            elif key.count(":") == 1:
                if DEBUG: print("Grabbing client {} flavour v1".format(keySplit[1]))
            else:
                print("Either less then 1 or more then 2 in line {}".format(key))
                # Implement mailer for errors mail("$ERROR")
                mail(subject="[DMA] key.count #fail", message="Either less then 1 or more then 2 in line {}".format(key))
        return x
        for e in k:
            # Create dictionary with index HEAD/modified
            try:
                flavour = e.decode('utf-8').split(':')[2]
                if not tasks.get(flavour):
                    tasks = { flavour : [] }
                tasks = { flavour : t}
            except IndexError:
                gotdata = 'null'
    else:
        t = grabTask(username,"v1")

def fetchTask(t, retmax):
    x = []
    at = list(t)
    at = [a for a in at if a != b'null']
    for task in sorted(at, key=lambda x: str(x), reverse=True)[:retmax]:
        ## IMPLEMENT MULTI INSTANCE
        if "-" in task.decode('utf-8'):
            uuidSubmission = task.decode('utf-8').split(":")[1]
            task = task.decode('utf-8').split(":")[0]
        else:
            task = task.decode('utf-8')
            uuidSubmission = None
        r = requests.get(BASE_URL[0]+TASKS_VIEW+task)
        if r.status_code == requests.codes.ok:
            j = json.loads(r.text)
            if uuidSubmission:
                j["task"]["uuid"] = uuidSubmission
            x.append(j)
        else:
            # Some times we get a bad response and need to handle it. This also serves as place-debug-holder to see what is include in the variable 'x'
            # To see what exactly does on, refer to DMAconfig.py
            x = xJSON # NB, this cariable comes from DMAconfig.py
    return x

def status(username, retmax=20, flavour="v1"):
    tasks = {}
    x = []

    # Check if we should limit the maximum analyses returned
    if retmax == 'all':
        retmax = -1
    else:
        retmax = int(retmax)

    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    k = red.keys()
    if len(k) >= 1:
        ## /!\ IMPLEMENT MULTI INSTANCE
        t = red.smembers("t:"+username+":modified")
        for e in k:
            # Create dictionary with index HEAD/modified
            try:
                flavour = e.decode('utf-8').split(':')[2]
                if not tasks.get(flavour):
                    tasks = { flavour : [] }
                tasks = { flavour : t}
            except IndexError:
                gotdata = 'null'
    else:
        t = red.smembers("t:"+username)
    at = list(t)
    # Skip entries that are null and entries that have no task ID
    at = [a for a in at if (a != b'null') and (a[:1] != b':')]
    for task in sorted(at, key=lambda x: int(x.split(b':')[0]), reverse=True)[:retmax]:
        ## /!\ IMPLEMENT MULTI INSTANCE
        if "-" in task.decode('utf-8'):
            task = task.decode('utf-8').split(":")[0]
        else:
            task = task.decode('utf-8')
        r = requests.get(BASE_URL[0]+TASKS_VIEW+task)
        if r.status_code == requests.codes.ok:
            j = json.loads(r.text)
            x.append(j)
        else:
            # Some times we get a bad response and need to handle it. This also serves as place-debug-holder to see what is include in the variable 'x'
            # To see what exactly does on, refer to DMAconfig.py
            x = xJSON # NB, this cariable comes from DMAconfig.py
    return x

def machines():
    ## IMPLEMENT MULTI INSTANCE
    r = requests.get(BASE_URL[0]+MACHINES_LIST)
    return json.loads(r.text)

def cuckooStatus():
    ## IMPLEMENT MULTI INSTANCE
    try:
        r = requests.get(BASE_URL[0]+CUCKOO_STATUS)
        return json.loads(r.text)
    except (IndexError, requests.exceptions.RequestException) as e:
        if DEBUG: print(e)
        return render_template('iamerror.html')


def checkURL():
    if request.headers.get('X-Forwarded-Host'):
        HOST=request.headers.get('X-Forwarded-Host')
        WEB_PATH=request.headers.get('X-Script-Name')
        PROTO=request.headers.get('X-Scheme')
        URL=PROTO+"://"+HOST+WEB_PATH
    else:
        URI=urlparse(url_for('.index', _external=True))
        HOST=re.split(':', URI[1])[0]
        URL=URI[0]+"://"+URI[1]
    return URL

def checkFlavour(flavour, redis):
    if flavour == "v1" or not flavour:
        t = redis.smembers("t:"+auth.username()+":HEAD")
        return t
    else:
        t = redis.smembers("t:"+auth.username()+":modified")
        return t

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
    # The following check is to make revers proxies happy
    if (HOST == MYPROXYHOST) or (HOST == MYPROXYHOST.replace("www.", "", 1)):
        return redirect('/dma/')
    else:
        return redirect('/')

@app.route('/dmabeta/')
@app.route('/dmabeta')
def dmabeta():
    # The following check is to make revers proxies happy
    if (HOST == MYPROXYHOST) or (HOST == MYPROXYHOST.replace("www.", "", 1)):
        return redirect('/dmabeta/')
    else:
        return redirect('/')

@app.route('/api', methods=['GET', 'POST'])
@auth.login_required
def api():
    if DEBUG: print("This is an API place-debug-holder")
    # Simple post for base64 encoded binary. Return uuid and map uuid to subsmission id
    # Submit and return uuid
    URL = checkURL()
    s = status(auth.username())
    m = machines()
    cs = cuckooStatus()
    username = auth.username()
    # Handle API POST
    if request.method == 'POST' and request.files['sample']:
        f = request.files['sample']
        if f:
            try:
                fExtension = f.filename.rsplit('.', 1)[1]
            except IndexError:
                fExtension = 'NaN'
            sfname = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], sfname))
            hash_sha256 = hashlib.sha256()
            with open(os.path.join(app.config['UPLOAD_FOLDER'], sfname), mode='rb') as fSum:
                for chunk in iter(lambda: fSum.read(4096), b''):
                    hash_sha256.update(chunk)
            fSumSHA256 = hash_sha256.hexdigest()
        r = redis.StrictRedis(host='localhost', port=6379, db=5)
        uuidSubmission = str(uuid4())
        for machine in m:
            r.rpush("submit", auth.username()+":"+app.config['UPLOAD_FOLDER']+"/"+sfname+":"+machine+":"+fExtension+":"+ uuidSubmission)
            if DEBUG: print("Submitting: {} to Machine: {}".format(str(sfname), machine))
        return render_template('api.json', s=s, uuidSubmission=uuidSubmission)
    if request.method == 'GET':
        return render_template('api.json')

@app.route('/sylph/', methods=['GET', 'POST'])
@app.route('/sylph', methods=['GET', 'POST'])
@auth.login_required
def sylph():
    retmax=20
    username = auth.username()
    cs = cuckooStatus()
    URL = checkURL()
    errors = "ERR"
    if request.method == 'POST':
        if request.form['retmax']:
            retmax = request.form['retmax']
            s = statusDevel(auth.username(), retmax=retmax)
        else:
            s = statusDevel(auth.username(), retmax=20)
        if request.form['errors']:
            if DEBUG: print(request.form.getlist('errors'))
            errors = request.form['errors']
        else:
            errors = ""
    if request.method == 'GET':
        s = statusDevel(auth.username())
    if username in ADMINS:
        return render_template('sylph.html', user=username, urlPath=URL, cuckooStatus=cs, s=s, retmax=retmax, errors=errors)
    else:
        e="Permission denied!"
        return render_template('iamerror.html', e=e, user=username)

@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def index():
    try:
        r = requests.get(BASE_URL[0]+CUCKOO_STATUS)
    except (IndexError, requests.exceptions.RequestException) as e:
        return render_template('iamerror.html', e=e)

    retmax=20

    if MAINTENANCE:
        chkTime = os.path.getmtime('static/img/online_communities.png')
        mt = getTime(time.time() - chkTime)
        URL = checkURL()
        username = auth.username()
        cs = cuckooStatus()
        if XKCD:
            try:
                maintenanceXKCD = xkcd.getRandomComic()
                xkcdLink = maintenanceXKCD.getAsciiImageLink()
            except:
                offlineComic = (b"static/img/online_communities.png", b"static/img/duty_calls.png")
                xkcdLink = offlineComic[random.randint(0,len(offlineComic))]
            return render_template('maintenance.html', user=username, urlPath=URL, cuckooStatus=cs, xkcd=xkcdLink.decode('ascii'), maintenanceTime=mt)
        else:
            return render_template('maintenance.html', user=username, urlPath=URL, cuckooStatus=cs, maintenanceTime=mt)
    else:
        with open('static/img/online_communities.png', 'a'):
            os.utime('static/img/online_communities.png', None)

    URL = checkURL()
    username = auth.username()
    if request.method == 'POST':
        if request.form['retmax']:
            retmax = request.form['retmax']
            s = status(auth.username(), retmax=retmax)
        else:
            s = status(auth.username())

    if request.method == 'GET':
        s = status(auth.username())

    m = machines()
    cs = cuckooStatus()
    return render_template('main.html', s=s, machines=m, urlPath=URL, user=username, cuckooStatus=cs, retmax=retmax)

@app.route('/upload', methods=['GET', 'POST'])
@auth.login_required
def upload():
    URL = checkURL()
    s = status(auth.username())
    m = machines()
    cs = cuckooStatus()
    username = auth.username()
    if request.method == 'POST' and request.files['sample'] and request.form['machine'] and request.form['package']:
        f = request.files['sample']
        if f:
            try:
                fExtension = f.filename.rsplit('.', 1)[1]
            except IndexError:
                fExtension = 'NaN'
            sfname = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], sfname))
            hash_sha256 = hashlib.sha256()
            with open(os.path.join(app.config['UPLOAD_FOLDER'], sfname), mode='rb') as fSum:
                for chunk in iter(lambda: fSum.read(4096), b''):
                    hash_sha256.update(chunk)
            fSumSHA256 = hash_sha256.hexdigest()
        r = redis.StrictRedis(host='localhost', port=6379, db=5)
        uuidSubmission = str(uuid4())
        r.rpush("submit", auth.username()+":"+app.config['UPLOAD_FOLDER']+"/"+sfname+":"+request.form['machine']+":"+request.form['package']+":"+ uuidSubmission)
        if DEBUG: print("Submitting: {}".format(str(sfname)))
    return render_template('main.html', upload=request.files['sample'], s=s, machines=m, urlPath=URL, user=username, cuckooStatus=cs, uuid=uuidSubmission)

@app.route('/pfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def pfetch(taskid, auth=auth, flavour="v1"):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    if str(taskid) in str(t):
        ## IMPLEMENT MULTI INSTANCE
        r = requests.get(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/pdf")
        return Response(r.content, mimetype='application/pdf')
    else:
        return "Not allowed"

@app.route('/rfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def rfetch(taskid, auth=auth, flavour="v1"):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    t = checkFlavour(flavour, red)
    if str(taskid) in str(t):
        ## IMPLEMENT MULTI INSTANCE
        if DEBUG: print(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/html")
        r = requests.get(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/html")
        return r.text
    else:
        return "Not allowed"

if __name__ == '__main__':
        app.run(host='0.0.0.0')
