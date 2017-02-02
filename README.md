# dma-frontend

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
sudo apt-get install python3-pip redis-tools redis-server jq mutt curl gnupg2 virtualenv virtualenv-wrapper
```

### Setup virtualenv

```
mkvirtualenv -p /usr/bin/python3 dma-frontend
# Add the following lines to your .bashrc/.zshrc/.whateverYourShellrc
--------8<--------
# virtualenv
export VIRTUALENVWRAPPER_PYTHON=$(which python3)
export WORKON_HOME=~/.virtualenvs
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
--------8<--------
```

### pip

Make sure your shell looks something like this: (dma-frontend) cuckoo@myHost:~$

If that is not the case: workong dma-frontend

```
sudo pip3 install -r requirements.txt
```

### Mailer

Make sure you have a mailer setup otherwise you will obviously not be able to receive reports

# License

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

* Copyright (C) 2015 [Alexandre Dulaunoy](https://twitter.com/adulau)
* Copyright (C) 2015-2017 [Steve Clement](https://twitter.com/SteveClement)
* Copyright (C) 2015-2017 [CIRCL - Computer Incident Response Center Luxembourg](https://circl.lu)
