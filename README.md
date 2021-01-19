# dma-frontend

![CIRCL DMA](https://www.circl.lu/assets/images/logos/start/logo-dma.png)

dma-frontend is a minimalist web frontend to support submissions into sandboxes like [Cuckoo](https://github.com/cuckoosandbox/cuckoo) and get the reports from the same location. It can be easily extended to support a series of analysis from the same sample submission.

## Requirements

### submit.sh

- redis-cli
- curl
- gpg
- jq
- mutt

### python3 modules

Since Flask v0.10 and Werkzeug 0.9 Python3 >= 3.3 is supported.
More [information here.](http://flask.pocoo.org/docs/0.12/python3/)

- flask
- flask-httpauth
- redis
- requests
- json

### Ubuntu installs via apt-get
```
sudo apt-get install python3-pip redis-tools redis-server jq mutt curl gnupg2 virtualenv virtualenvwrapper
```

### Setup virtualenv

```
pip3 install virtualenvwrapper
# Add the following lines to your .bashrc/.zshrc/.whateverYourShellrc
--------8<--------
# virtualenv
export VIRTUALENVWRAPPER_PYTHON=$(which python3)
export WORKON_HOME=~/.virtualenvs
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
--------8<--------
mkvirtualenv -p /usr/bin/python3 dma-frontend
```

### pip

Make sure your shell looks something like this: (dma-frontend) cuckoo@myHost:~$

If that is not the case: workon dma-frontend

```
pip3 install -r requirements.txt
```

### Adding basic auth users

Edit and run ```user-hash.py``` - The file is self explanatory and gives further instructions.

### Mailer

Make sure you have a mailer setup otherwise you will obviously not be able to receive reports

## Config bin/submit.sh

In the bin/submit.sh file you need to change the following 3 variables and 1 function:

```
CUCKOO_API_URL
ADMINS
SUBMISSION_MAIL
```

## Config web/DMAconfig.py

In the web/DMAconfig.py file you need to change the following 4 variables and 1 function:

```
ADMINS
BASE_URL
MYPROXYHOST
UPLOAD_FOLDER

def mail(to="your.address@example.com", subject="[DMA] #fail where is the subject", message="I pity you fool! Please provide a message."):
…
    msg['From'] = "dma-my-cuckoo-server@example.com"
…
    s = smtplib.SMTP('your-outgoing-smtp-that-relays-for-you.local')
    s.send_message(msg)
```

## Running with tmux

The frontend can be run in a tmux/screen environment. Below is a snapshot what it might look like

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
(cuckoo) cuckoo@cph:~/cuckoo/utils$ cd ~/cuckoo/utils && python api.py --host 0.0.0.0                                                                                                                   |
 * Running on http://0.0.0.0:8090/ (Press CTRL+C to quit)                                                                                                                                               |
127.0.0.1 - - [02/Feb/2017 17:07:42] "GET /cuckoo/status HTTP/1.1" 200 -                                                                                                                                |
                                                                                                                                                                                                        |
                                                                                                                                                                                                        |
                                                                                                                                                                                                        |
─────────────────────────────────────────────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────
(dma-frontend) cuckoo@my-cuckoo-server:~/dma-frontend/web$ python3 index.py                  │cuckoo@my-cuckoo-server:~/dma-frontend$ ./bin/submit.sh                                                   |
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)                                    │Checking for redis-cli and mutt (want to be in $PATH) will exit 1 if not found. Got redis-cli continuing… |
 * Restarting with stat                                                                      │Got mutt continuing…                                                                                      |
 * Debugger is active!                                                                       │# of cuckoo instances : 1                                                                                 |
 * Debugger pin code: 278-858-799                                                            │Checking API http://0.0.0.0:8090/cuckoo/status                                                            |
                                                                                             │You run cuckoo version 2.0-dev on cuckoo instance 0                                                       |
                                                                                             │                                                                                                          |
```

# I am error

## HTTPConnectionPool

This just means that we cannot connect to the cuckoo API on port 8090

```python
HTTPConnectionPool(host='localhost', port=8090): Max retries exceeded with url: /cuckoo/status (Caused by NewConnectionError('<requests.packages.urllib3.connection.HTTPConnection object at 0x106890e10>: Failed to establish a new connection: [Errno 61] Connection refused',))
```

## redis exceptions

If you pull the rug under redis or it dies, you will get a generic Werkzeug error. Just restart redis-server.

```python
redis.exceptions.ConnectionError: Error 61 connecting to localhost:6379. Connection refused.
```

# License

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

* Copyright (C) 2015 [Alexandre Dulaunoy](https://twitter.com/adulau)
* Copyright (C) 2015-2017 [Steve Clement](https://twitter.com/SteveClement)
* Copyright (C) 2015-2017 [CIRCL - Computer Incident Response Center Luxembourg](https://circl.lu)
