#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-
#

import os.path, sys, time, random
import requests, json, pickle
import hashlib
from flask import Flask, Response, render_template, url_for, request, g, redirect
from flask_httpauth import HTTPBasicAuth
from flask.ext.bcrypt import Bcrypt
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import CallbackDict
from urllib.parse import urlparse
from datetime import timedelta, datetime
from uuid import uuid4
from redis import Redis
import smtplib
from email.mime.text import MIMEText
import redis
import re


try:
    import xkcd
    XKCD = True
except ImportError:
    print("Disabling XKCD support, some unicorns are crying right now, some where :'(")
    XKCD = False

try:
  from DMAusers import *
except ImportError:
  sys.exit("Please create a file with a users dictionary in: DMAusers.py")

# Allowed extensions to be uploaded
ALLOWED_EXTENSIONS = set(['applet', 'bin', 'dll', 'doc', 'exe', 'html', 'ie', 'jar', 'pdf', 'vbs', 'xls', 'zip', 'jpg', 'jpeg', 'gif', 'png', 'tif', 'tiff', 'apk', 'cmd', 'bat', 'infected'])

# Configurables
MAINTENANCE  = False
DEBUG = True
BASE_URL = [ "http://crgb.circl.lu:8090", "http://crg.circl.lu:8090" ]
TASKS_VIEW = "/tasks/view/"
TASKS_REPORT = "/tasks/report/"
CUCKOO_STATUS = "/cuckoo/status"
MACHINES_LIST = "/machines/list"
ADMINS = [ "circl" ]

# Setup Flask
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config.from_object(__name__)
if DEBUG:
    app.config['DEBUG'] = True
    # Disable GET log, also disable Debug Log
    import logging
    log = logging.getLogger('werkzeug')
    log.disabled = False
else:
    app.config['DEBUG'] = False

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

def mail(to="steve.clement@circl.lu", subject="[DMA] #fail where is the subject", message="I pity you fool! Please provide a message."):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = "dma-crgb@circl.lu"
    msg['To'] = to
    s = smtplib.SMTP('cpb.circl.lu')
    s.send_message(msg)
    s.quit()

def grabTask(username, flavour="v1"):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    k = red.keys()
    if flavour == "v1" or not flavour:
        t = red.smembers("t:"+username)
    else:
        t = red.smembers("t:"+username+":"+ flavour)
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
    if len(k) > 1:
        for ke in k:
            key = ke.decode('utf-8')
            keySplit = key.split(":")
            if key.count(":") == 2:
                print("Grabbing client {} flavour {}".format(keySplit[1], keySplit[2]))
                t = grabTask(username, keySplit[2])
                #x.append(fetchTask(t, retmax))
                x = fetchTask(t, retmax)
            elif key.count(":") == 1:
                print("Grabbing client {} flavour v1".format(keySplit[1]))
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
            x = [{'task': {'guest': {'id': 42, 'name': 'Windows_reload', 'label': 'Windows_reload', 'task_id': 42, 'manager': 'VirtualBox', 'shutdown_on': '2016-02-13 00:36:16', 'started_on': '2016-02-13 00:33:56'}, 'target': '/tmp/cuckoo-tmp/upload_S6wOsp/calc.exe', 'priority': 1, 'sample_id': 19, 'shrike_refer': None, 'status': 'reported', 'anti_issues': None, 'processing_finished_on': None, 'signatures_started_on': None, 'signatures_finished_on': None, 'shrike_msg': None, 'custom': '', 'signatures_total': None, 'analysis_started_on': None, 'completed_on': '2016-02-13 00:36:16', 'dropped_files': None, 'options': '', 'reporting_started_on': None, 'package': 'exe', 'parent_id': None, 'enforce_timeout': False, 'clock': '2015-10-16 00:33:55', 'tags': [], 'machine_id': None, 'registry_keys_modified': None, 'timeout': 0, 'domains': None, 'platform': '', 'machine': 'Windows_7_ent_sp1_x86_en', 'processing_started_on': None, 'added_on': '2016-02-13 00:33:55', 'timedout': False, 'analysis_finished_on': None, 'errors': [], 'category': 'file', 'started_on': '2016-02-13 00:33:56', 'shrike_url': None, 'files_written': None, 'signatures_alert': None, 'reporting_finished_on': None, 'running_processes': None, 'api_calls': None, 'sample': {'md5': 'e9cc8c20b0e682c77b97e6787de16e5d', 'file_type': 'PE32 executable (GUI) Intel 80386, for MS Windows', 'sha256': 'ef854d21cbf297ee267f22049b773ffeb4c1ff1a3e55227cc2a260754699d644', 'crc32': '03C45201', 'sha512': '1a3b9b2d16a4404b29675ab1132ad542840058fd356e0f145afe5d0c1d9e1653de28314cd24406b85f09a9ec874c4339967d9e7acb327065448096c5734502c7', 'file_size': 115200, 'id': 42, 'ssdeep': '1536:Zl14rQcWAkN7GAlqbkfAGQGV8aMbrNyrf1w+noPvaeBsCXK15Zr6O:7mZWXyaiedMbrN6pnoXPBsr5ZrR', 'sha1': '8be674dec4fcf14ae853a5c20a9288bff3e0520a'}, 'id': 42, 'shrike_sid': None, 'memory': False, 'crash_issues': None}}]
    return x

def status(username, retmax=20):
    tasks = {}

    if retmax == 'all':
        retmax = -1
    else:
        retmax = int(retmax)

    red = redis.StrictRedis(host='localhost', port=6379, db=5)
    k = red.keys()
    if len(k) > 1:
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
    x = []
    at = list(t)
    at = [a for a in at if a != b'null']
    for task in sorted(at, key=lambda x: int(x.split(b':')[0]), reverse=True)[:retmax]:
        ## IMPLEMENT MULTI INSTANCE
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
            x = [{'task': {'guest': {'id': 42, 'name': 'Windows_reload', 'label': 'Windows_reload', 'task_id': 42, 'manager': 'VirtualBox', 'shutdown_on': '2016-02-13 00:36:16', 'started_on': '2016-02-13 00:33:56'}, 'target': '/tmp/cuckoo-tmp/upload_S6wOsp/calc.exe', 'priority': 1, 'sample_id': 19, 'shrike_refer': None, 'status': 'reported', 'anti_issues': None, 'processing_finished_on': None, 'signatures_started_on': None, 'signatures_finished_on': None, 'shrike_msg': None, 'custom': '', 'signatures_total': None, 'analysis_started_on': None, 'completed_on': '2016-02-13 00:36:16', 'dropped_files': None, 'options': '', 'reporting_started_on': None, 'package': 'exe', 'parent_id': None, 'enforce_timeout': False, 'clock': '2015-10-16 00:33:55', 'tags': [], 'machine_id': None, 'registry_keys_modified': None, 'timeout': 0, 'domains': None, 'platform': '', 'machine': 'Windows_7_ent_sp1_x86_en', 'processing_started_on': None, 'added_on': '2016-02-13 00:33:55', 'timedout': False, 'analysis_finished_on': None, 'errors': [], 'category': 'file', 'started_on': '2016-02-13 00:33:56', 'shrike_url': None, 'files_written': None, 'signatures_alert': None, 'reporting_finished_on': None, 'running_processes': None, 'api_calls': None, 'sample': {'md5': 'e9cc8c20b0e682c77b97e6787de16e5d', 'file_type': 'PE32 executable (GUI) Intel 80386, for MS Windows', 'sha256': 'ef854d21cbf297ee267f22049b773ffeb4c1ff1a3e55227cc2a260754699d644', 'crc32': '03C45201', 'sha512': '1a3b9b2d16a4404b29675ab1132ad542840058fd356e0f145afe5d0c1d9e1653de28314cd24406b85f09a9ec874c4339967d9e7acb327065448096c5734502c7', 'file_size': 115200, 'id': 42, 'ssdeep': '1536:Zl14rQcWAkN7GAlqbkfAGQGV8aMbrNyrf1w+noPvaeBsCXK15Zr6O:7mZWXyaiedMbrN6pnoXPBsr5ZrR', 'sha1': '8be674dec4fcf14ae853a5c20a9288bff3e0520a'}, 'id': 42, 'shrike_sid': None, 'memory': False, 'crash_issues': None}}]
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
    except requests.exceptions.RequestException as e:
        print(e)
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

@app.route('/api', methods=['GET', 'POST'])
@auth.login_required
def api():
    print("This is an API place-debug-holder")
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
        if f and allowed_file(f.filename):
            fExtension = f.filename.rsplit('.', 1)[1]
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
            print("Submitting: {} to Machine: {}".format(str(sfname), machine))
        return render_template('api.json', s=s, uuidSubmission=uuidSubmission)
    if request.method == 'GET':
        return render_template('api.json')

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
            print(request.form.getlist('errors'))
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
    except requests.exceptions.RequestException as e:
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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

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
        if f and allowed_file(f.filename):
            fExtension = f.filename.rsplit('.', 1)[1]
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
        print("Submitting: {}".format(str(sfname)))
    return render_template('main.html', upload=request.files['sample'], s=s, machines=m, urlPath=URL, user=username, cuckooStatus=cs, uuid=uuidSubmission)

@app.route('/pfetch/<int:taskid>', methods=['GET'])
@auth.login_required
def pfetch(taskid, auth=auth):
    red = redis.StrictRedis(host='localhost', port=6379, db=5)
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
    t = red.smembers("t:"+auth.username()+":modified")
    print(t)
    if str(taskid) in str(t):
        ## IMPLEMENT MULTI INSTANCE
        print(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/html")
        r = requests.get(BASE_URL[0]+TASKS_REPORT+str(taskid)+"/html")
        return r.text
    else:
        return "Not allowed"

if __name__ == '__main__':
        app.run(host='0.0.0.0')
