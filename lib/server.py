import pprint
import os
pp = pprint.PrettyPrinter(indent=4)
import sys
import asyncio
import uuid
import subprocess
import json
import base64
# https://asyncssh.readthedocs.io/en/latest/
import asyncssh
# https://pymongo.readthedocs.io/en/stable/examples/bulk.html
from pymongo import UpdateOne
# https://docs.aiohttp.org/en/stable/web_advanced.html
from aiohttp import web

from .controller import Controller
from .controller import WithController
from .util import get_utc_time
from .ssh import ControllerSSHServer

# Defaults
LOGIN_TIMEOUT = '30s'
KEEPALIVE = '30s'

RESERVED_PORT_RANGE = [40000, 50000]


# CONTROLLER SERVER
class ControllerServer(Controller):
  """
  Server controller class
  """


#### ##    ## #### ########    ########  ########  
 ##  ###   ##  ##     ##       ##     ## ##     ## 
 ##  ####  ##  ##     ##       ##     ## ##     ## 
 ##  ## ## ##  ##     ##       ##     ## ########  
 ##  ##  ####  ##     ##       ##     ## ##     ## 
 ##  ##   ###  ##     ##       ##     ## ##     ## 
#### ##    ## ####    ##       ########  ########  
  def init_db(self):
    """Initialize database collections and indexes

    """
    t = get_utc_time()

    # Controller Servers
    col = self.db_col('controllers')
    col.create_index( [ ("id", 1), ("controller_type", 1), ("status", 1) ] )

    # Client Nodes
    col = self.db_col('nodes')
    col.create_index( [ ("id", 1), ("controller_type", 1), ("status", 1) ] )

    # Connection tracking for tunnel sockets
    col = self.db_col('sockets')
    col.create_index( [ ("id", 1), ("key", 1) ] )

    # Port allocations for local forward tunnels
    col = self.db_col('ports')
    col.create_index( [ ("id", 1), ("node_id", 1)] )
    bulk_update = []
    for i in range(RESERVED_PORT_RANGE[0], RESERVED_PORT_RANGE[1]):
      update = { '$set': { 'id': i, 'node_id': None } }
      bulk_update.append( UpdateOne({ 'id': i }, update, upsert=True ) )
    # for
    result = col.bulk_write( bulk_update )

    # Eventlog
    db = None
    try:
      db = self.db_get_db()
      db.create_collection('events', max=1500, size=100000, capped=True)
    except:
      pass
    col = self.db_col('events')
    col.create_index( [ ("id", 1), ("time", 1), ("controller_id", 1), ("node_id", 1) ] )

    # FUTURE: Sites
    col = self.db_col('sites')
    col.create_index( [ ("id", 1), ("description", 1) ] )
    update = { 
      'id': 'default',
      'updatedAt': t,
      'description': 'Default Site'
    }
    col.update_one({ 'id': 'default' }, { '$set': update }, upsert=True )

    # FUTURE: Networking
    col = self.db_col('vlans')
    col.create_index( [ ("id", 1), ("tag", 1) ] )

    col = self.db_col('wlans')
    col.create_index( [ ("id", 1), ("tag", 1) ] )

    message = "Database initialized"
    self.log( level = 'info', message = message, store = True )
  # def



##     ## ######## ######## ########      ######  ######## ########  ##     ## ######## ########  
##     ##    ##       ##    ##     ##    ##    ## ##       ##     ## ##     ## ##       ##     ## 
##     ##    ##       ##    ##     ##    ##       ##       ##     ## ##     ## ##       ##     ## 
#########    ##       ##    ########      ######  ######   ########  ##     ## ######   ########  
##     ##    ##       ##    ##                 ## ##       ##   ##    ##   ##  ##       ##   ##   
##     ##    ##       ##    ##           ##    ## ##       ##    ##    ## ##   ##       ##    ##  
##     ##    ##       ##    ##            ######  ######## ##     ##    ###    ######## ##     ## 

  async def task_http_admin_server(self):
    # GET /healthcheck 
    async def healthcheck(request):
      return web.Response(text="OK")

    # GET /status
    async def status(request):
      return web.Response(text=self._status)
    # def

    # GET /connections
    async def connections(request):
      res = {}
      for c in self._connections['ssh']:
        obj = self._connections['ssh'][c]
        if(obj._owner):
          res[obj._uuid] = { "address": obj._peer_addr, "username": obj._username }
      return web.json_response(res)
    # def

    # https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html
    async def inventory(request = None):
      """Generating Ansible inventory

      Parameters: request

      Returns: json
      """
      col = None
      # TODO: Groups
      inv = { 
        'default': {
          'hosts': [],
          'vars': {},
          'children': []
        },
        '_meta': {
          'hostvars': {}
        }
      }

      query = {'status': 'online', 'disabled': False, 'node_type': 'ssh'}
      try:
        col_nodes = self.db_col('nodes')
        col_ports = self.db_col('ports')
        cur_nodes = col_nodes.find( query )
        for node in cur_nodes:
          ansible_user = 'admin'

          try:
            ansible_user = node['ssh_reverse_shell']['username']
          except:
            pass
          use_key = False
          try:
            use_key = node['ssh_reverse_shell']['use_key']
          except:
            pass

          inv['default']['hosts'].append(node['id'])
          inv['_meta']['hostvars'][node['id']] = {
            'ansible_connection': 'ssh',
            'ansible_user': ansible_user,
          }
          if use_key:
            inv['_meta']['hostvars'][node['id']]['ansible_ssh_private_key_file'] = "./nodes/%s/%s.key" % (node['id'], ansible_user)
          # if

          res = None
          try:
            res = col_ports.find_one({'node_id': node['id'], 'service': 'ssh'}, {'_id': False})
          except:
            pass

          if res:
            inv['_meta']['hostvars'][node['id']]['ansible_host'] = 'localhost'
            inv['_meta']['hostvars'][node['id']]['ansible_ssh_common_args'] = "-o UserKnownHostsFile=./nodes/%s/known_hosts -p %s" % (node['id'], res['id'])
          else:
            inv['_meta']['hostvars'][node['id']]['ansible_ssh_common_args'] = "-o UserKnownHostsFile=./nodes/%s/known_hosts -o \"ProxyCommand socat - UNIX-CLIENT:./nodes/%s/22.sock\"" % (node['id'], node['id'])
          self.log( level = 'debug', message = "Ansible Inventory generated for %s" % node['id'] )
        # for

      except Exception as exc:
        self.log( level = 'error', message = "Ansible Inventory Failed: %s" % exc, store = True )
      return web.json_response(inv)
    # def

    @web.middleware
    async def middleware(request, handler):
      # print('Middleware called')
      response = await handler(request)
      # print('Middleware finished')
      return response
    # def

    app = web.Application(middlewares=[middleware])
    app.router.add_get('/', healthcheck)
    app.router.add_get('/status', status)
    app.router.add_get('/connections', connections)
    app.router.add_get('/inventory', inventory)

    http_admin_port = self.config['http_admin_port']
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', http_admin_port)
    await site.start()
    message = "Controller HTTP Admin Server started"
    self.log( level = 'info', message = message, store = True )

    while True:
      await asyncio.sleep(3600)
  # def



 ######   ######  ##     ##     ######  ######## ########  ##     ## ######## ########  
##    ## ##    ## ##     ##    ##    ## ##       ##     ## ##     ## ##       ##     ## 
##       ##       ##     ##    ##       ##       ##     ## ##     ## ##       ##     ## 
 ######   ######  #########     ######  ######   ########  ##     ## ######   ########  
      ##       ## ##     ##          ## ##       ##   ##    ##   ##  ##       ##   ##   
##    ## ##    ## ##     ##    ##    ## ##       ##    ##    ## ##   ##       ##    ##  
 ######   ######  ##     ##     ######  ######## ##     ##    ###    ######## ##     ##

  async def handle_admin_client(self, process):
    """Starting an interactive adinstrator shell as a subprocess
    
    """

    # pp.pprint( self.__dirname__ )
    # SSH Username
    username = self._username = process.get_extra_info('username')
    # SSH Client IP Address
    peername = self._peername = process.get_extra_info('peername')[0]

    proc_path = os.path.join( self.__absdir__, 'adminshell' )
    # shell=True

    try:
      proc = subprocess.Popen( [proc_path], 
                                encoding = 'utf-8', 
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE, 
                                stderr = subprocess.PIPE )
      message = "Administrator Shell started for %s (%s)" % ( username, peername )
      self.log( level = 'info', message = message, node_id = username, store = True )
      await process.redirect( stdin = proc.stdin, 
                              stdout = proc.stdout,
                              stderr = proc.stderr )
      await process.stdout.drain()
    except Exception as exc:
      message = "Failed to start admin hell for %s (%s) - %s" % ( username, peername, exc )
      self.log( level = 'error', message = message, node_id = username, store = True )
    finally:
      process.close()
  # def


  # TODO: https://asyncssh.readthedocs.io/en/latest/#id15
  # ssh user_node_id@test... 
  async def handle_user_client(self, process):
    # pp.pprint( self.__dirname__ )
    # SSH Username
    username = self._username = process.get_extra_info('username')
    # SSH Client IP Address
    peername = self._peername = process.get_extra_info('peername')[0]

    # ssh with parameters a
    proc_path = os.path.join(self.__absdir__, 'usershell' )
    # shell=True

    try:
      proc = subprocess.Popen( [proc_path], 
                                encoding = 'utf-8', 
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE, 
                                stderr = subprocess.PIPE )
      message = "User Shell started for %s (%s)" % ( username, peername )
      self.log( level = 'info', message = message, node_id = username, store = True )
      await process.redirect( stdin = proc.stdin, 
                              stdout = proc.stdout,
                              stderr = proc.stderr )
      await process.stdout.drain()
    except Exception as exc:
      message = "Failed to start user shell for %s (%s) - %s" % ( username, peername, exc )
      self.log( level = 'error', message = message, node_id = username, store = True )
    finally:
      process.close()
  # def

  async def handle_ssh_client(self, process):
    controller_id = self.config['id']
    # SSH Username
    username = self._username = process.get_extra_info('username')
    # SSH Client IP Address
    peername = self._peername = process.get_extra_info('peername')[0]
    process.stdout.write("[%s] Press Ctrl+C to abort the connection...\n" % (controller_id))
    message = "PTY Session started (Node Address: %s)" % ( peername )
    self.log( level = 'info', message = message, node_id = username, store = True )
    try:
      process.stdout.write("\n[%s] [%s] > " % (controller_id, username))

      async for line in process.stdin:

        line = line.strip()
        if line == 'exit':
          return process.close()
        elif line == 'help':
          process.stdout.write("Show help" )
          process.stdout.write("\n[%s] [%s] > " % (controller_id, username))
          continue

        # Parse node JSON
        try:
          # self.log( level = 'debug', message = "line: %s" % line, node_id = username)
          line = base64.b64decode( line )
          # self.log( level = 'debug', message = "base64.b64decode( line ): %s" % line, node_id = username)
          line = line.decode("utf-8")
          # self.log( level = 'debug', message = "line.decode('utf-8'): %s" % line, node_id = username)
          node_json = json.loads( line )
          self.log( level = 'debug', message = "node_json: %s" % node_json, node_id = username)
          # # store to db
          self.db_update_node_json(node_id = username, node_json = node_json)
          process.stdout.write("[%s] Node JSON Accepted\n" % (controller_id))
        except Exception as exc:
          self.log( level = 'error', message = "Invalid node_json string %s" % exc, node_id = username, store = True)
          process.stdout.write("[%s] Node JSON Invalid\n" % (controller_id))
          pass
        finally:
          process.stdout.write("\n[%s] [%s] > " % (controller_id, username))
      
    except Exception as exc:
      mesage = "Connection closed with Exception: %s" % (exc)
      self.log( level = 'error', message = message, node_id = username, store = True)
      process.close()
  # def

########  ######## ##    ## 
##     ##    ##     ##  ##  
##     ##    ##      ####   
########     ##       ##    
##           ##       ##    
##           ##       ##    
##           ##       ##    

  # handle_client
  async def ssh_process_factory(self, process):
    """
    A callable or coroutine handler function which takes an AsyncSSH SSHServerProcess 
    argument that will be called each time a new shell, exec, or subsystem other than 
    SFTP is requested by the client. If set, this takes precedence over the session_factory argument.
    """

    t = get_utc_time()
    controller_id = self.config['id']
    # asyncssh.process.SSHServerProcess
    # self._process = process

    # SSH Username
    username = self._username = process.get_extra_info('username')
    # SSH Client IP Address
    # peername = self._peername = process.get_extra_info('peername')[0]
    # SSH Connectioon
    connection = self._connection = process.get_extra_info('connection')
    # pp.pprint(connection.__dict__)
    # pp.pprint(connection._owner.__dict__)
    node_type = connection._owner._node['node_type']

    # https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHClientConnection.get_extra_info
    client_version = process.get_extra_info('client_version')
    # server_version = process.get_extra_info('server_version')
    # send_cipher = process.get_extra_info('send_cipher')
    # send_mac = process.get_extra_info('send_mac')
    # send_compression = process.get_extra_info('send_compression')
    recv_cipher = process.get_extra_info('recv_cipher')
    recv_mac = process.get_extra_info('recv_mac')
    # recv_compression = process.get_extra_info('recv_compression')

    process.stdout.write("[%s] Connection established at: %s\n" % ( controller_id, t) )
    process.stdout.write("[%s] Your Client: %s %s %s %s\n" % (controller_id, username, client_version, recv_cipher, recv_mac ) )

    # https://asyncssh.readthedocs.io/en/latest/#id15
    # Handlers should call process.close()
    if node_type == 'ssh':
      return await self.handle_ssh_client(process)
    elif node_type == 'admin':
      return await self.handle_admin_client(process)
    elif node_type == 'user':
      return await self.handle_user_client(process)
    else:
      message = "Unknown node type (%s) for %s" % (username, node_type)
      self.log( level = 'error', message = message, node_id = username, store = True)
      process.close()
  # def

  # https://github.com/ronf/asyncssh/blob/875330da4bb0322d872f702dbb1f44c7e6137c48/asyncssh/connection.py#L405
  def ssh_acceptor(self, conn):
    """
    A callable or coroutine which will be called when the SSH handshake 
    completes on an accepted connection, taking the SSHServerConnection as an argument.

    Store accepted SSH connections for internal tracking
    """

    uid = str( uuid.uuid4() )
    conn._uuid = uid
    self._connections['ssh'][uid] = conn
  # def


  async def task_ssh_server(self):

    # TODO: kwargs
    @WithController( controller = self )
    class SSHServerWithController( ControllerSSHServer ):
      def __init__(self):
        pass
      # def
      def __del__(self):
        pass
    # class

    # https://asyncssh.readthedocs.io/en/latest/_modules/asyncssh/connection.html#create_server
    # https://asyncssh.readthedocs.io/en/latest/_modules/asyncssh/connection.html#listen
    # Options:
    # https://asyncssh.readthedocs.io/en/stable/api.html#asyncssh.SSHServerConnectionOptions

    bind_address = ''
    self.sshserver = await asyncssh.create_server( SSHServerWithController, 
                                              bind_address, self.config['ssh_port'],
                                              server_host_keys = self.config['ssh_host_keys'],
                                              host_based_auth = False,
                                              public_key_auth = True,
                                              password_auth = False,
                                              kbdint_auth = False,
                                              x11_forwarding = False,
                                              allow_scp = False,
                                              server_version = "SSHController",
                                              process_factory = self.ssh_process_factory,
                                              acceptor = self.ssh_acceptor,
                                              login_timeout = LOGIN_TIMEOUT,
                                              keepalive_interval = KEEPALIVE,
                                              keepalive_count_max = 1,
                                              tcp_keepalive = True )
    try:
      self.db_update_controller()
    except Exception as exc:
      self.log( level = 'error', message = "FATAL - %s" % ( exc ), store = True )
      # raise exc
      sys.exit(1)
    #
    self.log( level = 'info', message = "Controller SSH Server started", store = True)

    self.sshserver
  # def



   ###     ######  ##    ## ##    ##  ######     ##        #######   #######  ########  
  ## ##   ##    ##  ##  ##  ###   ## ##    ##    ##       ##     ## ##     ## ##     ## 
 ##   ##  ##         ####   ####  ## ##          ##       ##     ## ##     ## ##     ## 
##     ##  ######     ##    ## ## ## ##          ##       ##     ## ##     ## ########  
#########       ##    ##    ##  #### ##          ##       ##     ## ##     ## ##        
##     ## ##    ##    ##    ##   ### ##    ##    ##       ##     ## ##     ## ##        
##     ##  ######     ##    ##    ##  ######     ########  #######   #######  ##        

  def create_tasks(self, loop):
    # Services 
    # https://stackoverflow.com/questions/31623194/asyncio-two-loops-for-different-i-o-tasks
    loop.create_task( self.task_ssh_server() )
    loop.create_task( self.task_http_admin_server() )

    # Periodic Tasks
    loop.create_task( self.task_mark() )
    loop.create_task( self.task_usage() )
  # def
# class
