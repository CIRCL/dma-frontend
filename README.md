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
sudo apt-get install python3-pip redis-tools redis-server jq mutt curl gnupg2
```

### pip

```
sudo pip3 install -r requirements.txt
```

### Mailer

Make sure you have a mailer setup otherwise you will obviously not be able to receive reports
