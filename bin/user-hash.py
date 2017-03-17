#!/usr/bin/env python3

import sys
import json
import string
import random
import argparse
from shutil import copy2

try:
    import bcrypt
except ImportError:
    sys.exit("Install bcrypt please")

parser = argparse.ArgumentParser()

parser = argparse.ArgumentParser(description='Add User to DMA')
parser.add_argument("-u", "--user", required=True, help="Adds User to DMAusers.py and prints out a password.")

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

with open('../web/DMAusers.json', 'w') as outfile:
    json.dump(usersFromFile, outfile)
