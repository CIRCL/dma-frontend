#!/usr/bin/env python3.5

import sys

try:
    import bcrypt
except ImportError:
    sys.exit("Install bcrypt please")

users = {
    "circl": "myPlainTextPassword",
    "tat": "07b989f1e5482ba6eae783c0e7",
    "michelin-group": "aa2dd2447c3dd9a0b1da44a622aeb",
    "luxith": "ab6hh6748c3hd9a0b1ha49a622aeb",
    "fthill": "abch9abh4a2aeb",
    "raiffeisen.lu": "9ec1fbbc1edff192ad14639ce861a080402d6a1b",
}

print("users = {")
for key in users:
    print("    '{}': {},".format(key, bcrypt.hashpw(users[key].encode('utf-8'), bcrypt.gensalt(16))))
print("}")
