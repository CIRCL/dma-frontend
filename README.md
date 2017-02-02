# dma-frontend

## Requirements

### submit.sh

- redis-cli
- curl
- gpg
- jq
- mutt

### python3 modules

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
```

### pip

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
