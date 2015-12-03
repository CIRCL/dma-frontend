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
sudo apt-get install python3-pip redis-tools redis-server jq mutt curl gnupg2
```

### pip

```
sudo pip3 install -r requirements.txt
```

### Mailer

Make sure you have a mailer setup otherwise you will obviously not be able to receive reports
