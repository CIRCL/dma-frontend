# check for xkcd module, used in maintenance mode
try:
    import xkcd
    import sys
    import os
    import json
    XKCD = True
except ImportError:
    print("Disabling XKCD support, some unicorns are crying right now, some where :'(")
    XKCD = False

# check for hurry.filesize, used for easy kilobyte to human readable format
try:
    from hurry.filesize import size
except ImportError:
    sys.exit("Please pip install hurry.filesize")

# check for DMAusers file, needed to login and auth analyses
try:
    with open('DMAusers.json') as json_data_file:
        users = json.load(json_data_file)
except OSError:
    sys.exit("Please add a user with the bin/user-hash.py script")

# check if redis is running
try:
    import redis
    from redis import Redis
    rs = Redis("localhost")
    response = rs.client_list()
except redis.ConnectionError:
    sys.exit("Redis Connection Error? Is redis-server running?")

# this is bad style etc, but a dirty fix for now
# checking if run from main web app directory
try:
    goodPath = os.path.getmtime('static/img/online_communities.png')
except:
    sys.exit("You have to start index.py IN the web directory.")
