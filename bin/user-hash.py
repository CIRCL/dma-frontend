#!/usr/bin/env python3

import sys
import json
import string
import random
import argparse
from shutil import copy2
from pathlib import Path

try:
    import bcrypt
except ImportError:
    sys.exit("Install bcrypt please")

parser = argparse.ArgumentParser()

parser = argparse.ArgumentParser(description='Add User to DMA')
parser.add_argument("-u", "--user", required=True, help="Adds or Changes user-passwords and prints out a password.")

args = parser.parse_args()

def randomPassword():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    size = random.randint(16, 32)
    return ''.join(random.choice(chars) for x in range(size))

plainText = randomPassword()

users = {
    args.user:plainText,
}

try:
    with open('../web/DMAusers.json') as json_data_file:
        usersFromFile = json.load(json_data_file)
        copy2('../web/DMAusers.json', '../web/DMAusers.json.old')
except OSError:
        usersFromFile = {}

print("# User will be added or updated in web/DMAusers.json")
print("users = {")
for key in users:
    hashSalt = bcrypt.hashpw(users[key].encode('utf-8'), bcrypt.gensalt(16))
    print("    '{}': '{}', # <---- Plain-text version of password".format(key, plainText))
    print("    '{}': {},".format(key, hashSalt))
    users = { key:hashSalt.decode() }
    usersFromFile.update(users)
print("}")

# try/except hack to force user to be in bin/ directory

if Path.cwd().joinpath('web').is_dir():
    jsonPath = 'web/DMAusers.json'
    indexPath = 'web/index.py'
elif Path.cwd().joinpath('../web').is_dir():
    jsonPath = '../web/DMAusers.json'
    indexPath = '../web/index.py'
else:
    jsonPath = indexPath = '/dev/null'
    print('This is weird, I could NOT find the "web" directory, sending everything to /dev/null')
    print('/!\\ +++ NO USER ADDED +++ /!\\')

with open(jsonPath, 'w') as outfile:
    json.dump(usersFromFile, outfile)

# Cheap hack to touch index.py to reload python script after user
# change/addition. This will NOT work if debug mode is switched off.
Path(indexPath).touch()
