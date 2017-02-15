#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

import time, random, pprint, magic
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
import smtplib
from email.mime.text import MIMEText
import re

# Check sane environment
from checkModulesEtAl import *

# Configurables
from DMAconfig import *

from flask_debugtoolbar import DebugToolbarExtension

# Setup Flask
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config.from_object(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
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

def grabTask(redis):
    scardHEAD = redis.scard("t:"+auth.username()+":HEAD")
    scardModified = redis.scard("t:"+auth.username()+":modified")
    if scardModified > 0:
        t = redis.smembers("t:"+auth.username()+":modified")
        if scardHEAD > 0:
            tH = redis.smembers("t:"+auth.username()+":HEAD")
            for e in tH:
                print("Added:  {}".format(len(tH)))
                #t.add(e)
        return t
    elif scardHEAD > 0:
        t = redis.smembers("t:"+auth.username()+":HEAD")
        return t

def statusDevel(username, retmax=20):
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
                if DEBUG:
                    if keySplit[1] == "circl":
                        print(": count 2 - Grabbing client {} flavour {}".format(keySplit[1], flavour))
                t = grabTask(red)
                #x.append(fetchTask(t, retmax))
                x = fetchTask(t, retmax)
            elif key.count(":") == 1:
                if DEBUG:
                    if keySplit[1] == "circl":
                        print(": count 1 - Grabbing client {} flavour v1".format(keySplit[1]))
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
        t = grabTask(red)

def status(username, retmax=20):
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
        t = grabTask(red)
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
    # If a user has not submitted t is None and a list on it fails
    try:
        at = list(t)
    except:
        at = []
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

def cuckooStatus(URL=None, username=None):
    ## IMPLEMENT MULTI INSTANCE
    try:
        r = requests.get(BASE_URL[0]+CUCKOO_STATUS)
        return json.loads(r.text)
    except (IndexError, requests.exceptions.RequestException) as e:
        if DEBUG: print(e)
        return render_template('iamerror.html', e=e, user=username, urlPath=URL)


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

@app.route('/sylph', methods=['GET', 'POST'])
@auth.login_required
def sylph():
    retmax=20
    username = auth.username()
    URL = checkURL()
    cs = cuckooStatus(URL, username)
    if cs['version'] == '1.3-NG':
        diskFree = "Not available on cuckoo-modified host"
        loadAvg = loadAvg5 = loadAvg15 = 'NaN'
    else:
        diskFree = size(cs['diskspace']['analyses']['free'])
        loadAvg = '%.2f' % cs['cpuload'][0]
        loadAvg5 = '%.2f' % cs['cpuload'][1]
        loadAvg15 = '%.2f' % cs['cpuload'][2]
    taskStats = cs['tasks']
    errors = "ERR"
    if request.method == 'POST':
        if request.form['retmax']:
            retmax = request.form['retmax']
            s = status(username, retmax=retmax)
        else:
            s = status(username, retmax=20)
        if request.form['errors']:
            if DEBUG: print(request.form.getlist('errors'))
            errors = request.form['errors']
        else:
            errors = ""
    if request.method == 'GET':
        s = status(username)
    if username in ADMINS:
        return render_template('sylph.html',
            user=username,
            urlPath=URL,
            cuckooStatus=cs,
            s=s,
            retmax=retmax,
            errors=errors,
            taskStats=taskStats,
            diskFree=diskFree,
            loadAvg=loadAvg,
            loadAvg5=loadAvg5,
            loadAvg15=loadAvg15)
    else:
        e="Permission denied!"
        return render_template('iamerror.html', e=e, user=username, urlPath=URL)

@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def index():

    # Make sure, one last time, that the cuckoo API is up.
    URL = checkURL()
    try:
        r = requests.get(BASE_URL[0]+CUCKOO_STATUS)
    except (IndexError, requests.exceptions.RequestException) as e:
        return render_template('iamerror.html', e=e, urlPath=URL)

    username = auth.username()
    retmax=20

    # Toggle maintenance mode
    if MAINTENANCE:
        chkTime = os.path.getmtime('static/img/online_communities.png')
        mt = getTime(time.time() - chkTime)
        cs = cuckooStatus(URL, username)
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

    # Get form contents from POST
    if request.method == 'POST':
        if request.form['retmax']:
            retmax = request.form['retmax']
            s = status(username, retmax=retmax)
        else:
            s = status(username)

    # A simple get will only return the default status
    if request.method == 'GET':
        s = status(username)

    m = machines()
    cs = cuckooStatus(URL, username)
    #if DEBUG: print("Passing the following to template.\ns={} machines={}\nurlPath={}\nuser={}\ncuckooStatus={}\nretmax={}".format(s, m, URL, username, csp, retmax))
    return render_template('main.html', s=s, machines=m, urlPath=URL, user=username, cuckooStatus=cs, retmax=retmax)

@app.route('/upload', methods=['GET', 'POST'])
@auth.login_required
def upload():
    URL = checkURL()
    username = auth.username()
    uploadFolder = app.config['UPLOAD_FOLDER']
    s = status(username)
    m = machines()
    cs = cuckooStatus(URL, username)
    if request.method == 'POST' and request.files['sample'] and request.form['machine'] or request.form['package']:
        f = request.files['sample']
        if f:
            try:
                fExtension = f.filename.rsplit('.', 1)[1]
            except IndexError:
                fExtension = 'NaN'
            sfname = secure_filename(f.filename)
            f.save(os.path.join(uploadFolder, sfname))
            # libfilemagic to automagically upload and select correct type
            with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
                magik = m.id_filename(os.path.join(uploadFolder, sfname))
            hash_sha256 = hashlib.sha256()
            with open(os.path.join(uploadFolder, sfname), mode='rb') as fSum:
                for chunk in iter(lambda: fSum.read(4096), b''):
                    hash_sha256.update(chunk)
            fSumSHA256 = hash_sha256.hexdigest()
        r = redis.StrictRedis(host='localhost', port=6379, db=5)
        uuidSubmission = str(uuid4())
        execPackage = request.form['package']
        r.rpush("submit", username +":"+ uploadFolder +"/"+ sfname +":"+ request.form['machine'] +":"+ execPackage +":"+ uuidSubmission)
        if DEBUG: print("Submitting: {}".format(str(sfname)))
    return render_template('main.html', upload=request.files['sample'], s=s, machines=m, urlPath=URL, user=username, cuckooStatus=cs, uuid=uuidSubmission)

@app.route('/pfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def pfetch(taskid, auth=auth):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    # BUG: force modified
    t = red.smembers("t:"+auth.username()+":modified")
    if str(taskid) in str(t):
        ## IMPLEMENT MULTI INSTANCE
        r = requests.get(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/pdf")
        return Response(r.content, mimetype='application/pdf')
    else:
        return "Not allowed"

@app.route('/rfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def rfetch(taskid, auth=auth):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    t = grabTask(red)
    if str(taskid) in str(t):
        ## IMPLEMENT MULTI INSTANCE
        if DEBUG: print(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/html")
        r = requests.get(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/html")
        return r.text
    else:
        return "Not allowed"

if __name__ == '__main__':
        app.run(host='0.0.0.0')
