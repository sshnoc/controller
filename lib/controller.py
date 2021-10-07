
import signal
import os
import sys
import abc
import asyncio
import asyncssh
import re
import weakref
# import base64
# import jwt

# https://pymongo.readthedocs.io/en/stable/tutorial.html
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# https://github.com/davidlatwe/montydb
# from montydb import set_storage, MontyClient

# TODO: basic auth for the API
# Return JSON
# https://docs.aiohttp.org/en/stable/web_advanced.html
# from aiohttp import web

import pprint
pp = pprint.PrettyPrinter(indent=4)
pprint = pp.pprint

from .app import Application
from .util import get_utc_time
from .util import detect_external_ip
from .util import detect_geoip
from .util import using
from .util import valid_id, valid_port, valid_secret
# from .crypto import Crypto

## Default values
VERSION = '0.0.1'
# DB_VERSION = '0.0.1'
CONTROLLER_ID = 'controller'
CONTROLLER_TYPE = 'ssh'
SECRET='change_this_secret'

# Local REST Admin Interface
HTTP_ADMIN_PORT = 2120

# SSH Server Defaults
SSH_PORT = 2122

# Database
MONGO_URI = "mongodb://root:root@localhost"
MONGO_DB = 'sshnoc'
MONGO_TIMEOUT = 3 # s

# logging
MARK_TIMEOUT = 300 # s
USAGE_TIMEOUT = 600 # s

LOCAL_FORWARD_PORTS = [514]
REMOTE_FORWARD_PORTS = [22,80,443,8000]

## Decorators
def WithController( controller = None ):
  def decorator(klass):
    klass._controller = controller
    return klass
  return decorator
# def


 ######  ##          ###     ######   ######  
##    ## ##         ## ##   ##    ## ##    ## 
##       ##        ##   ##  ##       ##       
##       ##       ##     ##  ######   ######  
##       ##       #########       ##       ## 
##    ## ##       ##     ## ##    ## ##    ## 
 ######  ######## ##     ##  ######   ######  


## CONTROLLER SERVER
class Controller(Application):
  """General Controller Server"""

  # Internal connection tracking
  _connections = {
    'ssh': weakref.WeakValueDictionary(),
    # 'ws': weakref.WeakValueDictionary()
  }

  _status = "offline"

  @abc.abstractmethod
  def create_tasks(self, loop):
    pass

  @abc.abstractmethod
  def init_db(self):
    pass

  @abc.abstractmethod
  async def loop_exit(self):
    pass

  @abc.abstractmethod
  def auth_completed(self, node, extra_info ):
    pass

  def add_arguments(self):
    super().add_arguments()

    # General
    self.arg_parser.add_argument('--id', type = valid_id, 
                                  help="Controller ID (CONTROLLER_ID) Default: %s" % CONTROLLER_ID )
    self.arg_parser.add_argument('--dryrun', default = False, action='store_true', 
                                  help='Run a dryrun without starting SSH server' )
    self.arg_parser.add_argument('--forcestart', default=False, action='store_true',
                                  help='Force start the server without checking online status' )
    # self.arg_parser.add_argument('--pid', default = False, action='store_true', 
    #                               help='Use pid file' )

    # Database
    self.arg_parser.add_argument('--mongo_uri',help="MongoDB URI (MONGO_URI) Default: %s" % MONGO_URI )
    self.arg_parser.add_argument('--mongo_db',help="MongoDB Database (MONGO_DB) Default: %s" % MONGO_DB )
    self.arg_parser.add_argument('--init_db', help='Initialize Database', default=False, action='store_true' )
    self.arg_parser.add_argument('--init_rs', help='Initialize Replica Set', default=False, action='store_true' )

    # SSH Server
    self.arg_parser.add_argument('--genkeys', default = False, action='store_true',
                                  help='Generate SSH Server keys' )
    self.arg_parser.add_argument('--ssh_port',help="SSH Server Port (SSH_PORT) Default: %s" % SSH_PORT, type=valid_port )
    self.arg_parser.add_argument('--http_admin_port', type=valid_port, 
                                  help="HTTP Admin Port (HTTP_ADMIN_PORT) Default: %s" % HTTP_ADMIN_PORT )
  # def


##        #######   ######    ######   #### ##    ##  ######   
##       ##     ## ##    ##  ##    ##   ##  ###   ## ##    ##  
##       ##     ## ##        ##         ##  ####  ## ##        
##       ##     ## ##   #### ##   ####  ##  ## ## ## ##   #### 
##       ##     ## ##    ##  ##    ##   ##  ##  #### ##    ##  
##       ##     ## ##    ##  ##    ##   ##  ##   ### ##    ##  
########  #######   ######    ######   #### ##    ##  ######   

  def log(self, **kwargs ):
    """Low-level logging"""

    level = kwargs['level']
    message = kwargs['message']
    store = False
    node_id = ''
    try:
      store = kwargs['store']
    except:
      pass

    logger_message = message
    try:
      node_id = kwargs['node_id']
      logger_message = "[%s] %s" % (node_id, message)
    except:
      pass

    if level == 'error':
      self.logger.error("[%s] %s" % (self.config['id'], logger_message ) )
    elif level == 'debug':
      self.logger.debug("[%s] %s" % (self.config['id'], logger_message ) )
    elif level == 'important' or level == 'warning':
      self.logger.warning("[%s] %s" % (self.config['id'], logger_message ) )
    else:
      self.logger.info("[%s] %s" % (self.config['id'], logger_message ) )

    if store:
      event = {
        'controller_id': self.config['id'],
        'node_id': node_id,
        'controller_type': self.config['controller_type'],
        'message': message,
        'level': level
      }
      self.db_store_event(event)
  # def


#### ##    ## #### ######## 
 ##  ###   ##  ##     ##    
 ##  ####  ##  ##     ##    
 ##  ## ## ##  ##     ##    
 ##  ##  ####  ##     ##    
 ##  ##   ###  ##     ##    
#### ##    ## ####    ##    

  def init( self, controller_type = 'ssh', id = None ):
    """
    Initialize controller object configuration from cli arguments or the environment

    Parameters:
        controller_type (str): Type of the controller
    """
    # Controller Type
    self.config['controller_type'] = controller_type

    # Controller Id
    controller_id = CONTROLLER_ID
    try:
      controller_id = valid_id( os.environ['CONTROLLER_ID'] )
    except:
      pass
    if self.arguments.id:
      controller_id = self.arguments.id
    # Final override
    if id:
      controller_id = id
    self.config['id'] = controller_id
    self.log( level = 'info', message = "Id: %s (%s)" % (controller_id, controller_type))

    secret = SECRET
    try:
      secret = valid_secret( os.environ['SECRET'] )
    except:
      if secret == SECRET:
        self.log( level = 'warning', message = "Change default SECRET in .env file!" )
      # if
    self.config['secret'] = secret

    pid = os.getpid()
    self.log( level = 'info', message = "PID = %s" % pid)
    self.config['pid'] = pid

    # SSH specific initialization
    if self.arguments.genkeys:
      try:
        self.init_ssh_keys()
      except Exception as exc:
        self.log( level = 'error', message = "(init) %s" % repr(exc) )
      finally:
        sys.exit(1)

    if self.config['controller_type'] == 'ssh':
      try:
        self.init_directories()
        self.init_ssh_config()
      except FileExistsError:
        self.log( level = 'error', message = "FATAL - Cannot create node directory" )
        sys.exit(1)
      except FileNotFoundError:
        self.log( level = 'error', message = "FATAL - Missing SSH keys. Try to generate keys with genkey!" )
        sys.exit(1)
      except Exception as exc:
        self.log( level = 'error', message = "(init) %s" % repr(exc) )
        sys.exit(1)

      # HTTP-based Admin port for online status or config
      http_admin_port = HTTP_ADMIN_PORT
      try:
        http_admin_port = valid_port( os.environ['HTTP_ADMIN_PORT'] )
      except:
        pass
      try:
        if self.arguments.http_admin_port:
          http_admin_port = self.arguments.http_admin_port
      except:
        pass
      self.config['http_admin_port'] = http_admin_port
      self.log( level = 'info', message = "HTTP Admin Port: %s" % ( self.config['http_admin_port'] ) )
    # if

    # Database initialization
    self.init_mongo_config()
    # self.init_mongo()

    # Initilaize Database collections
    init_db = False
    try:
      init_db = self.arguments.init_db
    except:
      pass

    self.connect_mongo()
    self.init_db()
    if init_db:
      sys.exit(0)

    # Check Controller Status
    if not self.arguments.forcestart:
      if self.config['controller_type'] != 'shell':
        try:
          status = self.db_controller_status()
          if status == 'online':
            self.log( level = 'error', message = "FATAL - Controller with the same Id already started" )
            sys.exit(1)
        except Exception as exc:
          self.log( level = 'error', message = "(init) FATAL - %s" % ( exc ) )
          sys.exit(1)

    # Get External IP Address and GeoIP information
    if self.config['controller_type'] == 'ssh':
      external_ip = None
      geoip = None
      try:
        external_ip = detect_external_ip()
        geoip = detect_geoip(external_ip)
      except Exception as exc:
        self.log( level = 'error', message = exc )
        sys.exit(1)
      self.config['external_ip'] = external_ip
      self.config['geoip'] = geoip
      self.config['country'] = 'Unknown'
      if geoip:
        self.config['country'] = geoip['country']

      message = "SSH Server External Address: %s:%s (%s)" % ( self.config['external_ip'], self.config['ssh_port'], self.config['country'] )
      self.log( level = 'info', message = message )

    if self.arguments.dryrun:
      sys.exit(0)

  # def

  def init_directories(self):
    """
    Initialize directory structure for nodes
    """

    nodes_dir = os.path.join( self.__dirname__, "nodes" )
    if not os.path.exists(nodes_dir):
      os.makedirs(nodes_dir)
  # def

  def init_ssh_keys(self):
    controller_id = self.config['id']
    ssh_host_keys = {
      'ssh-rsa': os.path.join( self.__dirname__, 'ssh', "%s_host_rsa_key" % controller_id ),
      'ecdsa-sha2-nistp256': os.path.join( self.__dirname__, 'ssh', "%s_host_ecdsa_key" % controller_id ),
      'ssh-ed25519': os.path.join( self.__dirname__, 'ssh', "%s_host_ed25519_key" % controller_id )
    }
    
    for algo in ssh_host_keys:
      key_path = ssh_host_keys[algo]
      try:
        asyncssh.read_private_key(key_path)
        self.log( level = 'info', message = "SSH Key exists: %s" % key_path )
      except FileNotFoundError as exc:
        if( algo == 'ssh-rsa'):
          key = asyncssh.generate_private_key(algo, comment="sshserver", key_size=2048)
        else:
          key = asyncssh.generate_private_key(algo, comment="sshserver")
        key.write_private_key( key_path )
        key.write_public_key( "%s.pub" % key_path )
        self.log( level = 'info', message = "New SSH Generated: %s" % key_path )
      # except: KeyGenerationError as exc:
      except Exception as exc:
        self.log( level = 'error', message = "(init_ssh_keys) %s" % repr(exc) )
  # def

  def init_ssh_config(self):
    # Default forward ports
    self.config['ssh_local_forward_ports'] = LOCAL_FORWARD_PORTS
    self.config['ssh_remote_forward_ports'] = REMOTE_FORWARD_PORTS

    # SSH Server Port
    ssh_port = SSH_PORT
    try:
      ssh_port = valid_port( os.environ['SSH_PORT'] )
    except Exception as exc:
      pass

    if self.arguments.ssh_port:
      ssh_port = self.arguments.ssh_port
    self.config['ssh_port'] = ssh_port

    # SSH Server Host Keys
    controller_id = self.config['id']
    ssh_host_keys = [
      os.path.join( self.__dirname__, 'ssh', "%s_host_rsa_key" % controller_id ),
      os.path.join( self.__dirname__, 'ssh', "%s_host_ecdsa_key" % controller_id ),
      os.path.join( self.__dirname__, 'ssh', "%s_host_ed25519_key" % controller_id )
    ]

    self.config['ssh_host_keys'] = {}
    for key_path in ssh_host_keys:
      key = asyncssh.read_private_key(key_path)
      algo = key.get_algorithm()
      pubkey = key.convert_to_public()
      pubkey_str = pubkey.export_public_key(format_name='openssh').decode("utf-8").rstrip()
      fp = pubkey.get_fingerprint()
      self.config['ssh_host_keys'][key_path] = {
        'algo': algo,
        'pubkey_str': pubkey_str,
        'fp': fp
      }
      message = "Loading Host Key: %s (%s) %s" % (os.path.basename(key_path), fp, algo )
      self.log( level = 'info', message = message )
    # for
  # def

  def init_mongo_config(self):
    """
    Initilaize MongoDB config
    """

    mongo_uri = MONGO_URI
    try:
      mongo_uri = os.environ['MONGO_URI']
    except:
      pass
    if self.arguments.mongo_uri:
      mongo_uri = self.arguments.mongo_uri
    self.config['mongo_uri'] = mongo_uri
  
    mongo_db = MONGO_DB
    try:
      mongo_db = os.environ['MONGO_DB']
    except:
      pass
    self._mongo_db = mongo_db
    if self.arguments.mongo_db:
      mongo_db = self.arguments.mongo_db
    self.config['mongo_db'] = mongo_db
  # def



########     ###    ########    ###    ########     ###     ######  ######## 
##     ##   ## ##      ##      ## ##   ##     ##   ## ##   ##    ## ##       
##     ##  ##   ##     ##     ##   ##  ##     ##  ##   ##  ##       ##       
##     ## ##     ##    ##    ##     ## ########  ##     ##  ######  ######   
##     ## #########    ##    ######### ##     ## #########       ## ##       
##     ## ##     ##    ##    ##     ## ##     ## ##     ## ##    ## ##       
########  ##     ##    ##    ##     ## ########  ##     ##  ######  ######## 


  def connect_mongo(self):
    mongo_uri = self.config['mongo_uri']
    mongo_db = self.config['mongo_db']
    mongo_uri_masked = "%s/%s" % ( re.sub(r'\/.*@', '//***@', mongo_uri), self.config['mongo_db'])
    self.config['mongo_uri_masked'] = mongo_uri_masked
    self.log( level = 'debug', message = "Connecting Database (%s)" % mongo_uri_masked )
    self.mongo_client = None
    # TODO: SSL params from cli

    serverSelectionTimeoutMS = MONGO_TIMEOUT * 1000
    try:
      self.mongo_client = MongoClient( mongo_uri,
                                      serverSelectionTimeoutMS = serverSelectionTimeoutMS,
                                      tls=os.environ['MONGO_SSL'],
                                      tlsCAFile= os.environ['MONGO_SSL_CA_CERTS'], 
                                      tlsCertificateKeyFile=os.environ['MONGO_SSL_CERTFILE'],
                                      ssl_keyfile=os.environ['MONGO_SSL_KEYFILE'] )
    except:
      self.mongo_client = MongoClient( mongo_uri, serverSelectionTimeoutMS = serverSelectionTimeoutMS )

    db_status = None
    try:
      # The ismaster command is cheap and does not require auth.
      db_status = self.mongo_client.admin.command( 'ismaster' )
      self.log( level = 'info', message = "Database Connected (%s)" % mongo_uri_masked )
    except ConnectionFailure as exc:
      self.log( level = 'error', message = "FATAL - Database connection failed: %s - %s" % ( mongo_db, exc ) )
      if self.config['controller_type'] == "shell":
        self.log( level = 'error', message = "ERROR - Database connection failed: %s - %s" % ( mongo_db, exc ) )
        self.log( level = 'error', message = "Shell started with reduced functionality" )
        return False
      # or die
      sys.exit(1)

    # Initialize Replica Set
    if self.arguments.init_rs:
      rs = self.mongo_client.admin.command("replSetInitiate")
      self.log( level = 'info', message = "Replica Set: %s (%s)" % (rs.info2, rs.me) )
    # if

  # def

  def db_get_db(self):
    return self.mongo_client[ self.config['mongo_db'] ]

  def db_col(self, col = None ):
    db = self.db_get_db()
    return db[col]
  # def

  def db_store_event(self, event = None):
    t = get_utc_time()
    col = self.db_col('events')
    event['createdAt'] = t
    col.insert_one(event)
  # def

  # Database
  def db_update_controller(self):
    t = get_utc_time()
    col = self.db_col('controllers')
    query = { 'id': self.config['id'] }
    update = {
      'controller_type': self.config['controller_type'],
      'ssh_host_keys': self.config['ssh_host_keys'],
      'ssh_port': self.config['ssh_port'],
      'external_ip': self.config['external_ip'],
      'geoip': self.config['geoip'],
      'updatedAt': t
    }
    col.update_one( query, { '$set': update }, upsert=True )
  # def

  def db_update_controller_status( self, status = 'offline' ):
    t = get_utc_time()
    col = self.db_col('controllers')
    query = { 'id': self.config['id'] }
    update = { 'status': status, 'updatedAt': t }
    col.update_one( query, { '$set': update }, upsert=True )
  # def

  def controller_online(self):
    # TODO: transaction
    t = get_utc_time()
    col_nodes = self.db_col('nodes')
    controller_type = self.config['controller_type']
    controller_id = self.config['id']
    query = {
      'controller_id': controller_id, 
      'node_type': controller_type
    }
    update = { 'status': 'offline', 'updatedAt': t }
    self.db_update_controller_status('online')
    col_nodes.update_many( query, { '$set': update } )

    if controller_type == 'ssh':
      col_tunnels = self.db_col('tunnels')
      query = { 'controller_id': controller_id }
      update = { 'status': 'offline', 'updatedAt': t }
      col_tunnels.update_many( query, { '$set': update } )
    # if
    self.log( level = 'info', message = "Controller is Online", store = True )
    self._status = "online"
  # def


  # TODO: server_type ws
  def controller_offline(self):
    # TODO: transaction
    t = get_utc_time()
    col_nodes = self.db_col('nodes')
    controller_type = self.config['controller_type']
    controller_id = self.config['id']
    query = {
      'controller_id': controller_id, 
      'node_type': controller_type
    }
    update = { 'status': 'controller', 'updatedAt': t, 'disconnectedAt': t }
    self.db_update_controller_status('offline')
    col_nodes.update_many( query, { '$set': update } )

    if controller_type == 'ssh':
      col_tunnels = self.db_col('tunnels')
      query = { 'controller_id': controller_id }
      update = { 'status': 'controller', 'updatedAt': t }
      col_tunnels.update_many( query, { '$set': update } )
    # if
    self.log( level = 'info', message = "Controller is Offline", store = True)
  # def

  def db_find_node( self, query ):
    col = self.db_col('nodes')
    node = col.find_one( query )
    return(node)
  # def

  def db_update_node(self, query, update):
    col = self.db_col('nodes')
    ret = col.update_one( query, update )
    return ret
  # def

  def db_update_node_json(self, node_id, node_json):
    t = get_utc_time()
    col = self.db_col('nodes')
    query = { 'id': node_id }
    update = { 'node_json': { 'status': node_json, 'updatedAt': t } }
    ret = col.update_one( query, { '$set': update } )
    # pp.pprint(ret)
    return ret
  # def

  def db_controller_status( self ):
    col = self.db_col( 'controllers' )
    query = { 'id': self.config['id'] }
    res = col.find_one( query, { '_id': False, 'status': True } )
    try:
      return res['status']
    except:
      return None
  # def



##        #######   #######  ########  
##       ##     ## ##     ## ##     ## 
##       ##     ## ##     ## ##     ## 
##       ##     ## ##     ## ########  
##       ##     ## ##     ## ##        
##       ##     ## ##     ## ##        
########  #######   #######  ##        

  # Stop the loop concurrently
  async def loop_stop(self):
    loop = asyncio.get_event_loop()
    await self.loop_exit()
    loop.stop()
  # def

  def shutdown(self):
    try:
      self.controller_offline()

      for task in asyncio.all_tasks():
        task.cancel()
      #
      asyncio.ensure_future( self.loop_stop() )

      # check for pid
      pid_path = os.path.join(self.__dirname__, "%s.pid" % self.config['id'])
      if os.path.exists(pid_path):
        os.remove(pid_path)
      else:
        pass
        # self.log( level = 'info', message = "Can not delete the pid file as it doesn't exists" )

      self.log( level = 'info', message = "Controller shutdown finished", store = True )
    #
    except Exception as exc:
      self.log( level = 'error', message = "FATAL - Controller Shutdown error: %s" % (exc) )
      sys.exit(1)
  # def

  def sigint(self):
    self.log( level = 'info', message = "SIGNAL - Controller got signal: SIGINT" )
    self.shutdown()

  def sigterm(self):
    self.log( level = 'info', message = "SIGNAL - Controller got signal: SIGTERM" )
    self.shutdown()



########  ##     ## ##    ##    ##        #######   #######  ########  
##     ## ##     ## ###   ##    ##       ##     ## ##     ## ##     ## 
##     ## ##     ## ####  ##    ##       ##     ## ##     ## ##     ## 
########  ##     ## ## ## ##    ##       ##     ## ##     ## ########  
##   ##   ##     ## ##  ####    ##       ##     ## ##     ## ##        
##    ##  ##     ## ##   ###    ##       ##     ## ##     ## ##        
##     ##  #######  ##    ##    ########  #######   #######  ##        

  def run(self):
    """
    Start asyncio event loop
    """

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, self.sigint)
    loop.add_signal_handler(signal.SIGTERM, self.sigterm)

    # Creating asyncio server tasks (server.py create_tasks)
    self.create_tasks( loop )

    # Set controller online status
    self.controller_online()
    loop.run_forever()
  # def

########    ###     ######  ##    ##  ######  
   ##      ## ##   ##    ## ##   ##  ##    ## 
   ##     ##   ##  ##       ##  ##   ##       
   ##    ##     ##  ######  #####     ######  
   ##    #########       ## ##  ##         ## 
   ##    ##     ## ##    ## ##   ##  ##    ## 
   ##    ##     ##  ######  ##    ##  ######  

  ## MARK
  async def task_mark(self):
    while True:
      self.log( level = 'info', message = "-- MARK --")
      await asyncio.sleep( MARK_TIMEOUT )
  # def

  async def task_usage(self):
    col = self.db_col('nodes')
    while True:
      query = {'status': 'online'}
      total = col.count_documents({})
      online = col.count_documents(query)
      self.log( level = 'debug', message = "Controller Usage: %s" % ( using() ) )
      self.log( level = 'info', message = "Node Stats (online/total): %s/%s" % ( online, total ) )
      # TODO: force clean closed connections and write statistics in DB
      await asyncio.sleep( USAGE_TIMEOUT )
  # def
