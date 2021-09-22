
from dotenv import load_dotenv
from datetime import datetime
from datetime import timezone
from dateutil import tz
import urllib.request

# https://pythonhosted.org/python-geoip/
from geoip import geolite2

# https://stackoverflow.com/questions/552744/how-do-i-profile-memory-usage-in-python
import resource

# https://stackify.com/python-garbage-collection/
import gc

# https://stackoverflow.com/questions/36640436/python-garbage-collection-memory-no-longer-needed-not-released-to-os
import psutil

# https://docs.python-cerberus.org/
import cerberus

IP_DETECTORS = [
  "https://ipinfo.io/ip",
  "https://ifconfig.me/ip",
  "https://icanhazip.com",
  "https://ifconfig.co"
]

def using():
  '''Get basic memory usage and GC information'''
  maxrss = "maxrss: {:.2f}MiB".format(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
  vmem = "vmem: {:.2f}MiB".format(psutil.virtual_memory().used / 1024 ** 2)
  return "%s  %s  %s / %s"%(maxrss,vmem, gc.get_count(), gc.get_threshold() )
# def

# https://stackoverflow.com/questions/4770297/convert-utc-datetime-string-to-local-datetime
def utc2local(time = None, to_zone = tz.tzlocal() ):
  from_zone = tz.gettz('UTC')
  # to_zone = tz.gettz('America/New_York')
  utc = time # datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
  # Tell the datetime object that it's in UTC time zone since 
  # datetime objects are 'naive' by default
  utc = utc.replace(tzinfo=from_zone)
  # Convert time zone
  return utc.astimezone(to_zone)
# def


def get_utc_time():
  '''Get current UTC time'''
  dt = datetime.now(timezone.utc)
  utc_time = dt.replace(tzinfo=timezone.utc)
  return utc_time
# def

def detect_external_ip():
  '''Detect external IP by one of the detectors above'''
  for d in IP_DETECTORS:
    try:
      with urllib.request.urlopen(d) as response:
        return response.read().decode('utf-8')
    except:
      continue
  raise Exception('External IP was not found')
# def


def detect_geoip( ip = None ):
  """Get basic GeoIP information

  Parameters:
    ip (string): IP Address
  """
  ipinfo = {}
  try:
    ipinfo = geolite2.lookup(ip).to_dict()
    ipinfo['location'] = list(ipinfo['location'])
    del ipinfo['subdivisions']
    return ipinfo
  except Exception as exc:
    raise Exception("GeoIP was not found for %s" % ip )
# def

## Validators
def valid_id(astring = None):
  schema = {'id': {'type': 'string', 'maxlength': 32, 'minlength': 1, 'regex': r"^[a-zA-Z0-9]*$" }}
  v = cerberus.Validator()
  if v.validate( {'id': astring}, schema ):
    return astring
  raise Exception("Ivalid node id string")

def valid_port(astring = None ):
  schema = {'id': {'type': 'integer', 'min': 1025 }}
  v = cerberus.Validator()
  astring = int(astring)
  if v.validate( {'id': astring}, schema ):
    return astring
  raise Exception("Ivalid node port number")
