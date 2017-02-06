ADMINS = [ "yourBasicAuthAdminUsername" ]
UPLOAD_FOLDER = "/Users/steve/Desktop/code/dma-frontend/web/static/upload/"
MAINTENANCE  = False
DEBUG = True
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
