#!/usr/bin/env python3.6

import sys
import json
import string
import random
import pprint
import argparse
import hmac, hashlib, codecs
from shutil import copy2
from pathlib import Path
from validate_email import validate_email

try:
    import bcrypt
except ImportError as err:
    sys.exit("Install bcrypt please")

parser = argparse.ArgumentParser()

parser = argparse.ArgumentParser(description='Add User to DMA and/or bind VM to user')
parser.add_argument("-u", "--user", required=False, help="\
Adds or Changesuser-passwords and prints out a plaint-text password.")
parser.add_argument("-s", "--star", required=False, help="\
Adds or Changes user-tied-VM, user -s VMbaseName(64char):shortDescription(8char) ")
parser.add_argument("-l", "--list", required=False, action="store_true", help="\
List users and custom bound VMs, add -u to check if user exists")

# Put passed arguments into args
args = parser.parse_args()

# Check if username is a valid email address
def chkUsername(user):
    return validate_email(user, check_mx=True)

if not args.user and not args.list:
    parser.print_help()
    sys.exit("Please specify user or list mode")

if Path.cwd().joinpath('web').is_dir():
    jsonPath = 'web/DMAusers.json'
    jsonVMsPath = 'web/DMAvms.json'
    indexPath = 'web/index.py'
elif Path.cwd().joinpath('../web').is_dir():
    jsonPath = '../web/DMAusers.json'
    jsonVMsPath = '../web/DMAvms.json'
    indexPath = '../web/index.py'
else:
    jsonPath = jsonVMsPath = indexPath = '/dev/null'
    print('This is weird, I could NOT find the "web" directory, sending everything to /dev/null')
    print('/!\\ +++ NO USER ADDED OR MODIFIED +++ /!\\')

# Backup current Password file
def backup():
    global usersFromFile
    global VMsFromFile

    try:
        with open(jsonPath) as json_data_file:
            usersFromFile = json.load(json_data_file)
            copy2(jsonPath, jsonPath + '.old')
    except OSError as err:
            usersFromFile = {}

    try:
        with open(jsonVMsPath, "rb") as json_vms_data_file:
            VMsFromFile = json.load(json_vms_data_file)
            copy2(jsonVMsPath, jsonVMsPath + '.old')
    except OSError as err:
        VMsFromFile = {}

def listAll():
    pp = pprint.PrettyPrinter(indent=4)
    print("--------Current users-----------------------------------------------------------")
    pp.pprint(usersFromFile)
    print("--------Current custom VMs------------------------------------------------------")
    pp.pprint(VMsFromFile)

if args.list and not args.user and not args.star:
    backup()
    listAll()
    sys.exit("Currently {} registered users and {} custom bound VMs.".format(len(usersFromFile), len(VMsFromFile)))

if args.list and args.user:
    backup()
    listAll()
    if args.user in usersFromFile:
        print("--------------------------------------------------------------------------------")
        print("{} has an account on DMA".format(args.user))
    else:
        print("--------------------------------------------------------------------------------")
        print("{} has NO account on DMA".format(args.user))
    print("--------------------------------------------------------------------------------")
    sys.exit("Currently {} registered users and {} custom bound VMs.".format(len(usersFromFile), len(VMsFromFile)))

# returns a random password with chars upper/lower/digits between 16 and 32 in size
def randomPassword():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    size = random.randint(16, 32)
    return ''.join(random.choice(chars) for x in range(size))

# Make a backup of current user files
backup()

if args.star:
    user = bytes(args.user, 'utf-8')
    baseVM = bytes(args.star, 'utf-8')
    if ":" in args.star:
        descriptor = args.star.split(":")[1]
        baseVM = bytes(args.star.split(":")[0], 'utf-8')
    else:
        descriptor = "custoVM"

    saltedUser = user + bytes(randomPassword(), 'utf-8')
    m = hmac.new(saltedUser, digestmod=hashlib.blake2s)
    m.update(baseVM)
    hashVal = m.hexdigest()
    VMname = baseVM.decode('utf-8') + '_' + descriptor + '_' + hashVal
    print("--------------------------------------------------------------------------------")
    print("""VM name needs to be:
    {}
to bind to user {}""".format(VMname, user.decode('utf-8')))
    print("--------------------------------------------------------------------------------")

    vms = {
        args.user:VMname
    }
    print("# Custom VM binding will be added or updated in web/DMAvms.json")
    print("vms = {")
    for key in vms:
        vms = { key:VMname }
        print("    '{}': '{}',".format(key, VMname))
        VMsFromFile.update(vms)
    print("}")

    with open(jsonVMsPath, 'w') as outfileVMs:
        json.dump(VMsFromFile, outfileVMs)
    sys.exit("Done!")

plainText = randomPassword()
users = {
    args.user:plainText,
}

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
