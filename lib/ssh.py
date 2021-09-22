import os
import re
import asyncssh
from collections import UserDict

from .util import detect_geoip
from .util import get_utc_time

class SocketDict(UserDict):
  def __init__(self, dict=None, owner=None, **kwargs):
  # def __init__(self, dict=None, /, owner=None, **kwargs):
    self._owner = owner
    super().__init__(dict, **kwargs)
  # def

  def __setitem__(self, key, val):
    super().__setitem__(key, val)
    self._owner.socket_online(key,val)
  # def

  def __getitem__(self, key):
    val = super().__getitem__(key)
    return val
  # def

  def __delitem__(self, key):
    super().__delitem__(key)
    self._owner.socket_offline(key)
  # def
# class


# TODO: external file
## SSHSERVER CLASS
class ControllerSSHServer(asyncssh.SSHServer):
  """ https://asyncssh.readthedocs.io/en/latest/_modules/asyncssh/server.html """

  def log(self, **kwargs ):
    self._controller.log(**kwargs)
  # def

########     ###    ########    ###    ########     ###     ######  ######## 
##     ##   ## ##      ##      ## ##   ##     ##   ## ##   ##    ## ##       
##     ##  ##   ##     ##     ##   ##  ##     ##  ##   ##  ##       ##       
##     ## ##     ##    ##    ##     ## ########  ##     ##  ######  ######   
##     ## #########    ##    ######### ##     ## #########       ## ##       
##     ## ##     ##    ##    ##     ## ##     ## ##     ## ##    ## ##       
########  ##     ##    ##    ##     ## ########  ##     ##  ######  ########

  ## NODES
  def db_find_node(self, id = None ):
    return self._controller.db_find_node( { 'id': id } )
  # def

  def db_update_node_status(self, id = None, status='offline', extra_info = None):
    t = get_utc_time()
    query = {"id": id }
    controller_id = self._controller.config['id']
    update = { 
      'status': status, 
      'updatedAt': t, 
      'controller_id': controller_id,
    }
    if status == 'online':
      update['connectedAt'] = t
    elif status == 'offline':
      update['disconnectedAt'] = t

    if(extra_info):
      update['extra_info'] = extra_info
    return self._controller.db_update_node( query, { '$set': update } )
  # def

  def node_online(self, username = None, extra_info = None ):
    self.log( level = 'info', message = 'Node is Online: %s' % (username) )
    return self.db_update_node_status(username, 'online', extra_info )
  # def

  def node_offline(self, username = None ):
    self.log( level = 'info', message = 'Node is Offline: %s' % (username) )
    return self.db_update_node_status(username, 'offline')
  # def

  ## SOCKETS
  def socket_online(self, key = None, value = None, type = None ):
    t = get_utc_time()
    col = self._controller.db_col('sockets')
    controller_id = self._controller.config['id']
    query = { 'key': "%s:%s" % (controller_id, key) }
    update = { 
      'status': 'online',
      'node_id': self._username,
      'updatedAt': t, 
      'controller_id': controller_id,
      'listen_key': value._listen_key,
      'listen_port': value._listen_port,
      'type': type
    }
    return col.update_one( query, { '$set': update }, upsert = True )
  # def

  def socket_offline(self, key = None ):
    t = get_utc_time()
    col = self._controller.db_col('sockets')
    controller_id = self._controller.config['id']
    query = { 'key': "%s:%s" % (controller_id, key) }
    update = { 
      'status': 'offline',
      'node_id': self._username, 
      'updatedAt': t, 
      'controller_id': controller_id
    }
    return col.update_one( query, {'$set': update }, upsert = True )
  # def

 ######   #######  ##    ## ##    ## ########  ######  ######## ####  #######  ##    ## 
##    ## ##     ## ###   ## ###   ## ##       ##    ##    ##     ##  ##     ## ###   ## 
##       ##     ## ####  ## ####  ## ##       ##          ##     ##  ##     ## ####  ## 
##       ##     ## ## ## ## ## ## ## ######   ##          ##     ##  ##     ## ## ## ## 
##       ##     ## ##  #### ##  #### ##       ##          ##     ##  ##     ## ##  #### 
##    ## ##     ## ##   ### ##   ### ##       ##    ##    ##     ##  ##     ## ##   ### 
 ######   #######  ##    ## ##    ## ########  ######     ##    ####  #######  ##    ## 

  def connection_made(self, conn):
    """This method is called when a new TCP connection is accepted. 
    The conn parameter should be stored if needed for later use.

    https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.connection_made
    """

    self._conn = conn
    self._authorized_keys = None
    self._username = None
    self._extra_info = None
    self._peername = conn.get_extra_info('peername')[0]
    # Override default _local_listeners array with a Mongo-backed one
    self._conn._local_listeners = SocketDict(owner=self)
    self.log( level = 'debug', message = "connection_made %s" % (self._peername) )
  # def

  def connection_lost(self, exc):
    """This method is called when a connection is closed. If the connection is shut down cleanly, 
    exc will be None. Otherwise, it will be an exception explaining the reason for the disconnect.

    https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.connection_lost
    """

    if exc:
      message = "%s" % ( exc )
      self.log( level = 'error', message = message, node_id = self._username, store = True )
      # raise exc
    else:
      message = "Connection closed for %s" % (self._peername)
      self.log( level = 'info', message = message, node_id = self._username, store = True )

    if not self._username:
      return True

    username = self._username
    try:
      self.node_offline(username)
    except Exception as exc:
      message = "Unable to set node offline status: %s" % (exc),
      self.log( level = 'error', message = message, node_id = username )
      return False
  # def

   ###    ##     ## ######## ##     ## ##    ## ######## ######## ####  ######     ###    ######## ####  #######  ##    ## 
  ## ##   ##     ##    ##    ##     ## ###   ## ##          ##     ##  ##    ##   ## ##      ##     ##  ##     ## ###   ## 
 ##   ##  ##     ##    ##    ##     ## ####  ## ##          ##     ##  ##        ##   ##     ##     ##  ##     ## ####  ## 
##     ## ##     ##    ##    ######### ## ## ## ######      ##     ##  ##       ##     ##    ##     ##  ##     ## ## ## ## 
######### ##     ##    ##    ##     ## ##  #### ##          ##     ##  ##       #########    ##     ##  ##     ## ##  #### 
##     ## ##     ##    ##    ##     ## ##   ### ##          ##     ##  ##    ## ##     ##    ##     ##  ##     ## ##   ### 
##     ##  #######     ##    ##     ## ##    ## ########    ##    ####  ######  ##     ##    ##    ####  #######  ##    ## 

  def begin_auth(self, username):
    """This method will be called when authentication is attempted for the specified user. 
    Applications should use this method to prepare whatever state they need to complete the 
    authentication, such as loading in the set of authorized keys for that user. If no 
    authentication is required for this user, this method should return False to cause 
    the authentication to immediately succeed. Otherwise, it should return True to indicate 
    that authentication should proceed. If blocking operations need to be performed to 
    prepare the state needed to complete the authentication, this method may be defined 
    as a coroutine.

    https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.begin_auth
    """

    self.log( level = 'debug', message = "begin_auth started", node_id = username )
    self._username = username

    self._node = None
    self._client_keys = None
    self._ports = None

    # Get extra information from the connection and from GeoIP
    self._extra_info = dict()
    self._extra_info['client_version'] = self._conn.get_extra_info('client_version')
    self._extra_info['server_version'] = self._conn.get_extra_info('server_version')
    self._extra_info['send_cipher'] = self._conn.get_extra_info('send_cipher')
    self._extra_info['send_mac'] = self._conn.get_extra_info('send_mac')
    self._extra_info['send_compression'] = self._conn.get_extra_info('send_compression')
    self._extra_info['recv_cipher'] = self._conn.get_extra_info('recv_cipher')
    self._extra_info['recv_mac'] = self._conn.get_extra_info('recv_mac')
    self._extra_info['recv_compression'] = self._conn.get_extra_info('recv_compression')
    self._extra_info['peername'] = self._peername
    self._extra_info['geoip'] = { 'country': 'Unknown' }
    try:
      self._extra_info['geoip'] = detect_geoip(self._peername)
    except Exception as exc:
      pass

    try:
      self._node = self.db_find_node( id = username )
    except Exception as exc:
      message = "%s" % ( exc )
      self.log( level = 'error', message = message, node_id = username )
      return True
    #

    if not self._node:
      message = "Node not found"
      self.log( level = 'error', message = message, node_id = username )
      return True
    #

    if self._node['disabled']:
      message = "Node disabled"
      self.log( level = 'info', message = message, node_id = username )
      return True
    #

    # Get Allocated Forward Ports
    ports = []
    try:
      col_ports = self._controller.db_col('ports')
      res = col_ports.find( { 'node_id': username }, { '_id': False, 'id': True} )
      ports = []
      for r in res:
        ports.append(r['id'])
      # self.log( level = 'debug', message = "Port: %s" % ports, node_id = username )
    except:
      pass
    self._ports = ports

    # Get Redirect Ports
    # Allowed Controller ports redirect and open on the node
    try:
      self._node['ssh_local_forward_ports']
    except:
      self._node['ssh_local_forward_ports'] = self._controller.config['ssh_local_forward_ports']
    # Allowed Client ports redirect to the Controller as Socket
    try:
      self._node['ssh_remote_forward_ports']
    except:
      self._node['ssh_remote_forward_ports'] = self._controller.config['ssh_remote_forward_ports']

    # Get Authentication Keys - Load public key from the Database
    # https://github.com/ronf/asyncssh/blob/875330da4bb0322d872f702dbb1f44c7e6137c48/tests/test_connection_auth.py#L177
    # https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.load_public_keys
    # https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.import_public_key
    node_ssh_pubkey = None
    try:
      node_ssh_pubkey = asyncssh.import_public_key( bytes (self._node['ssh_pubkey'], 'utf-8' ) )
      if self._authorized_keys:
        self._conn.set_authorized_keys(self._authorized_keys)
      else:
        self._client_keys = asyncssh.load_public_keys( [node_ssh_pubkey] )
      return True
    except Exception as exc:
      message = "%s" % ( exc )
      self.log( level = 'error', message = message, node_id = username )
      return True
  # def

  def auth_completed(self):
    """This method is called when authentication has completed succesfully. 
    Applications may use this method to perform processing based on the authenticated 
    username or options in the authorized keys list or certificate associated with 
    the user before any sessions are opened or forwarding requests are handled.
    
    https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.auth_completed"""
    message = "Authentication completed (Client version: %s)" % ( self._extra_info['client_version'] )
    self.log( level = 'info', message = message, node_id = self._username, store = True )

    if hasattr(self._controller, 'auth_completed'):
      self._controller.auth_completed( node = self._node, extra_info = self._extra_info )
  # def

  def password_auth_supported(self):
    return False
  # def

  def validate_password(self, username, password):
    return False
  # def

  # Only public key authentication is supported
  def public_key_auth_supported(self):
    return True
  # def

  # TODO: ecdsa or ed keys
  # TODO: async and await for mongodb validation
  def validate_public_key(self, username, key):
    """Key based client authentication can be supported by passing authorized keys in the 
    authorized_client_keys argument of create_server(), or by calling set_authorized_keys 
    on the server connection from the begin_auth() method. However, for more flexibility 
    in matching on the allowed set of keys, this method can be implemented by the application 
    to do the matching itself. It should return True if the specified key is a valid client 
    key for the user being authenticated.

    This method may be called multiple times with different keys provided by the client. 
    Applications should precompute as much as possible in the begin_auth() method so that this 
    function can quickly return whether the key provided is in the list.

    If blocking operations need to be performed to determine the validity of the key, 
    this method may be defined as a coroutine.

    https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.validate_public_key"""

    if not self._node:
      self.log( level = 'debug', message = "Node not found", node_id = username )
      return False

    if not self._client_keys:
      self.log( level = 'debug', message = "Client key not found", node_id = username )
      return False

    if(key not in self._client_keys):
      self.log( level = 'debug', message = "Client key is invalid", node_id = username )
      return False

    # TODO: Geoip Check
  
    # Explicit key check
    # https://github.com/ronf/asyncssh/blob/875330da4bb0322d872f702dbb1f44c7e6137c48/tests/test_connection_auth.py#L177
    user_key_type = key.get_algorithm()
    user_key_fp = key.get_fingerprint()
    db_key = self._client_keys[0]
    db_key_type = db_key.get_algorithm()
    db_key_fp = db_key.get_fingerprint()
    self._extra_info['user_key_type'] = user_key_type
    self._extra_info['user_key_fp'] = user_key_fp

    try:
      node = self.node_online(username, self._extra_info )
    except Exception as exc:
      message = "%s" % ( exc )
      self.log( level = 'error', message = message, node_id = username )
      # Continue with authentication, verify key will fail
      return False
    #try

    if not node:
      message = "Node not found"
      self.log( level = 'error', message = message, node_id = username )
      # Continue with authentication, verify key will fail
      return False
    #if

    # Node Directory
    node_dir = os.path.join( self._controller.__dirname__, "nodes", "%s" % username )
    if not os.path.exists(node_dir):
      try:
        os.makedirs(node_dir)
      except Exception as exc:
        message = "Cannot create node directory: %s" % node_dir
        self.log( level = 'error', message = message, node_id = self._username, store = True )
        return False
    #if

    message = "Public Key Accepted for %s - %s" % ( self._peername, user_key_fp )
    self.log( level = 'debug', message = message, node_id = username )
    return True
  # def

########  #######  ########  ##      ##    ###    ########  ########  #### ##    ##  ######   
##       ##     ## ##     ## ##  ##  ##   ## ##   ##     ## ##     ##  ##  ###   ## ##    ##  
##       ##     ## ##     ## ##  ##  ##  ##   ##  ##     ## ##     ##  ##  ####  ## ##        
######   ##     ## ########  ##  ##  ## ##     ## ########  ##     ##  ##  ## ## ## ##   #### 
##       ##     ## ##   ##   ##  ##  ## ######### ##   ##   ##     ##  ##  ##  #### ##    ##  
##       ##     ## ##    ##  ##  ##  ## ##     ## ##    ##  ##     ##  ##  ##   ### ##    ##  
##        #######  ##     ##  ###  ###  ##     ## ##     ## ########  #### ##    ##  ######   


  ## Local Port Forwarding: ssh ... -L orig_port:dest_host:dest_port ... jumphost
  # Connection on local to orig_port goes to dest_host:dest_port via jumphost
  # TODO:
  # .tunnels
  # LP orig_port dest_port
  # eg. LP 1514 514
  def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
    """https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.connection_requested
    This method is called when a direct TCP/IP connection request is received by the server. 
    Applications wishing to accept such connections must override this method. To allow standard 
    port forwarding of data on the connection to the requested destination host and port, this 
    method should return True.

    Parameters:	
      dest_host (str) – The address the client wishes to connect to
      dest_port (int) – The port the client wishes to connect to
      orig_host (str) – The address the connection was originated from
      orig_port (int) – The port the connection was originated from
    """

    if( dest_host == 'localhost' and dest_port in self._node['ssh_local_forward_ports'] ):
      message = "Allow Local Port Forward %s:%s > %s:%s" % ( orig_host, orig_port, dest_host, dest_port )
      self.log( level = 'info', message = message, node_id = self._username, store = True )
      return True
    # if

    message = "Deny Local Port Forward %s:%s > %s:%s" % ( orig_host, orig_port, dest_host, dest_port )
    self.log( level = 'info', message = message, node_id = self._username, store = True )
    return False
  # def

  ## Local Socket Forwarding: -L dest_path:dest_host:dest_port
  # TODO: remove LS
  def unix_connection_requested(self, dest_path):
    """https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.unix_connection_requested
    This method is called when a direct UNIX domain socket connection request is received by the server. 
    Applications wishing to accept such connections must override this method. To allow standard path 
    forwarding of data on the connection to the requested destination path, this method should return True.

    Parameters:
      dest_path (str) – The path the client wishes to connect to
    """

    message = "Deny Local Socket Forward: %s" % ( dest_path )
    self.log( level = 'info', message = message, node_id = self._username, store = True )
    return False
  # def

  ## Remote Port Forwarding
  #  -R listen_port:listen_host:orig_port
  # TODO: RP
  def server_requested(self, listen_host, listen_port):
    """https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.server_requested
    This method is called when a client makes a request to listen on an address and port for incoming TCP 
    connections. The port to listen on may be 0 to request a dynamically allocated port. Applications wishing 
    to allow TCP/IP connection forwarding must override this method. To set up standard port forwarding 
    of connections received on this address and port, this method should return True.

    Parameters:	
      listen_host (str) – The address the server should listen on
      listen_port (int) – The port the server should listen on, or the value 0 to request that the server 
                          dynamically allocate a port
  
    Links:
      https://github.com/ronf/asyncssh/blob/875330da4bb0322d872f702dbb1f44c7e6137c48/asyncssh/connection.py#L4838
      https://github.com/ronf/asyncssh/blob/875330da4bb0322d872f702dbb1f44c7e6137c48/asyncssh/connection.py#L2471
      https://github.com/ronf/asyncssh/blob/875330da4bb0322d872f702dbb1f44c7e6137c48/asyncssh/connection.py#L5261
    """

    if( listen_host == 'localhost' and listen_port in self._ports):
      message = "Accept Remote Port Forward > %s:%s" % ( listen_host, listen_port )
      self.log( level = 'info', message = message, node_id = self._username, store = True )
      return True
    # if

    message = "Deny Remote Port Forward > %s:%s" % ( listen_host, listen_port )
    self.log( level = 'info', message = message, node_id = self._username, store = True )
    return False
  # def

  ## Remote Socket Forwarding
  #  -R listen_path:listen_host:orig_port
  def unix_server_requested(self, listen_path):
    """https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHServer.unix_server_requested
    This method is called when a client makes a request to listen on a path for incoming UNIX domain socket 
    connections. Applications wishing to allow UNIX domain socket forwarding must override this method. To set up 
    standard path forwarding of connections received on this path, this method should return True.

    Parameters:
      listen_path (str) – The path the server should listen on
    """

    # TODO: get_socket_path
    socket_path = "./nodes/%s/[1-9][0-9]+.sock" % self._username

    if( re.fullmatch( socket_path, listen_path) ):
      socket_port = int( os.path.splitext( os.path.basename( listen_path ) )[0] )
      # if socket_port in self._controller.config['ssh_remote_forward_ports']:
      if socket_port in self._node['ssh_remote_forward_ports']:
        message = "Accept Remote Socket Forward: %s (%s)" % ( listen_path, socket_port )
        self.log( level = 'info', message = message, node_id = self._username, store = True )
        return True
    #if

    message = "Deny Remote Socket Forward: %s" % ( listen_path )
    self.log( level = 'info', message = message, node_id = self._username, store = True )
    return False
  # def
# class
