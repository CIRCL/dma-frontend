# Admin username list
ADMINS = [ "yourBasicAuthAdminUsername", "yourOtherBasicAuthUsername" ]
# Location of file uploads
UPLOAD_FOLDER = "/Users/steve/Desktop/code/dma-frontend/web/static/upload/"
# If you have no reverse-proxy, leave as-is
MYPROXYHOST="www.example.com"
# Enabling maintenance mode will display either a stock XKCD or a dynamic one
MAINTENANCE  = False
# This will output startup config and enable Flask-DebugToolBar
DEBUG = False
# One cuckoo instance
BASE_URL = [ "http://my-cuckoo-server.local:8090" ]
# Two cuckoo instances
#BASE_URL = [ "http://my-cuckoo-server.local:8090", "http://my-cuckoo-modified-server.local:8090" ]
TASKS_VIEW = "/tasks/view/"
TASKS_REPORT = "/tasks/report/"
CUCKOO_STATUS = "/cuckoo/status"
MACHINES_LIST = "/machines/list"

def mail(to="your.address@example.com", subject="[DMA] #fail where is the subject", message="I pity you fool! Please provide a message."):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = "dma-my-cuckoo-server@example.com"
    msg['To'] = to
    s = smtplib.SMTP('your-outgoing-smtp-that-relays-for-you.local')
    s.send_message(msg)
    s.quit()
