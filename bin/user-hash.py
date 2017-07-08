#!/usr/bin/env python3.6

import sys
import json
import string
import random
import argparse
import hmac, hashlib
from shutil import copy2
from pathlib import Path
from validate_email import validate_email

try:
    import bcrypt
except ImportError:
    sys.exit("Install bcrypt please")

parser = argparse.ArgumentParser()

parser = argparse.ArgumentParser(description='Add User to DMA and/or bind VM to user')
parser.add_argument("-u", "--user", required=True, help="Adds or Changes user-passwords and prints out a password.")
parser.add_argument("-s", "--star", required=False, help="Adds or Changes user-tied-VM to flat json file.")

# Put passed arguments into args
args = parser.parse_args()

if Path.cwd().joinpath('web').is_dir():
    jsonPath = 'web/DMAusers.json'
    indexPath = 'web/index.py'
elif Path.cwd().joinpath('../web').is_dir():
    jsonPath = '../web/DMAusers.json'
    indexPath = '../web/index.py'
else:
    jsonPath = indexPath = '/dev/null'
    print('This is weird, I could NOT find the "web" directory, sending everything to /dev/null')
    print('/!\\ +++ NO USER ADDED OR MODIFIED +++ /!\\')

def backup():
    global usersFromFile

    try:
        with open(jsonPath) as json_data_file:
            usersFromFile = json.load(json_data_file)
            copy2(jsonPath, jsonPath + '.old')
    except OSError:
            usersFromFile = {}

def chkUsername(user):
    return validate_email(user, check_mx=True)

def randomPassword():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    size = random.randint(16, 32)
    return ''.join(random.choice(chars) for x in range(size))

plainText = randomPassword()

if args.star:
    print("So you want to bind user: {} with VM: {}".format(args.user, args.star))
    m = hmac.new(b'steve@localhost.lu', digestmod=hashlib.blake2s)
    m.update(b'Windows_7_ent_sp1_x86_en')
    # Basename
    # Windows_7_ent_sp1_x86_en
    # Full Name
    # Windows_7_ent_sp1_x86_en_HintOnWhatIsSpecialAboutVM_HashUser
    baseVM = args.star
    descriptor = "HintOnWhatIsSpecialAboutVM"
    hashVal = m.hexdigest()
    print(m.hexdigest())
    VMname = baseVM + '_' + descriptor + '_' + hashVal
    print("You need to have a VM named: {} to bind to this user".format(VMname))

users = {
    args.user:plainText,
}

if not chkUsername(args.user):
    sys.exit("The username wants to be an e-mail address, {} is not valid.".format(args.user))

# Make a backup of current user file
backup()

print("# User will be added or updated in web/DMAusers.json")
print("users = {")
for key in users:
    hashSalt = bcrypt.hashpw(users[key].encode('utf-8'), bcrypt.gensalt(16))
    print("    '{}': '{}', # <---- Plain-text version of password".format(key, plainText))
    print("    '{}': {},".format(key, hashSalt))
    users = { key:hashSalt.decode() }
    usersFromFile.update(users)
print("}")


with open(jsonPath, 'w') as outfile:
    json.dump(usersFromFile, outfile)

# Cheap hack to touch index.py to reload python script after user
# change/addition. This will NOT work if debug mode is switched off.
Path(indexPath).touch()
