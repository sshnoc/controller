import json
import asyncssh

from .controller import Controller
from .util import get_utc_time
from .util import utc2local
from .util import valid_id

# https://robpol86.github.io/terminaltables/
from terminaltables import AsciiTable

# https://github.com/noahmorrison/chevron
import chevron

# https://pymongo.readthedocs.io/en/stable/examples/bulk.html
from pymongo import UpdateOne, ASCENDING, DESCENDING

import pprint
pp = pprint.PrettyPrinter(indent=4)

######## ######## ##     ## ########  ##          ###    ######## ########  ######  
   ##    ##       ###   ### ##     ## ##         ## ##      ##    ##       ##    ## 
   ##    ##       #### #### ##     ## ##        ##   ##     ##    ##       ##       
   ##    ######   ## ### ## ########  ##       ##     ##    ##    ######    ######  
   ##    ##       ##     ## ##        ##       #########    ##    ##             ## 
   ##    ##       ##     ## ##        ##       ##     ##    ##    ##       ##    ## 
   ##    ######## ##     ## ##        ######## ##     ##    ##    ########  ######  

MUS_SHOW_CONTROLLER = """
   Id (Ext. Address): {{ id }} ({{ external_ip }})
  Country (Timezone): {{ country }} ({{ timezone }})
            SSH Port: {{ ssh_port }}
              Status: {{ status }}
"""

MUS_SHOW_NODE = """
   Id (Ext. Address): {{ id }} ({{ external_ip }})
  Country (Timezone): {{ country }} ({{ timezone }})
  SSH Client Version: {{ client_version }}
 Ciphers (send/recv): {{ send_cipher }} / {{ recv_cipher }}
    MACs (send/recv): {{ send_mac }} / {{ recv_mac }}
  System Description: {{ description }}
      System Product: {{ product }}
       System Serial: {{ serial }}
              Status: {{ status }}
             Updated: {{ updatedAt }}
           Connected: {{ connectedAt }}
        Disconnected: {{ disconnectedAt }}
             Created: {{ createdAt }}
"""


class ControllerWithAPI(Controller):

  # show events
  def api_show_events( self, limit = 30, node_id = None, controller_id = None ):
    """
    List events
    """

    if(limit > 500 or limit < 1):
      raise Exception("Limit is between 1 to 500")
    valid_id(node_id)
    valid_id(controller_id)

    t = get_utc_time()
    query = {}

    if node_id != 'all':
      query['node_id'] = node_id
    if controller_id != 'all':
      query['controller_id'] = controller_id

    try:
      col = self.db_col('events')
      cur = col.find( query, projection={"_id": False} ).sort( "createdAt", -1 ).limit(limit)
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc)
      return

    table = []
    table.append([ "Severity", "Created (UTC)", "Controller", "Node", "Message"] )
    for c in cur:
      row = [
        c['level'], c['createdAt'], c['controller_id'], c['node_id'], c['message']
      ]
      table.append( row )
    print( AsciiTable(table).table ) 
  # def

  # show controllers
  def api_show_controllers( self, type = None, status = None ):
    """
    List controllers
    """

    if not status in ['all', 'online', 'offline']:
      raise Exception("Unknown status: %s" % status )

    t = get_utc_time()
    count = {'total': 0, 'online': 0, 'offline': 0}
    cur = None
    query = {}
    if type:
      query['type'] = type
    if status != 'all':
      query['status'] = status
    try:
      col = self.db_col('controllers')
      cur = col.find( query, projection={"_id": False}).sort("id")
      count['total'] = col.count_documents( query )
      count['online'] = col.count_documents( {'status': 'online'} )
      count['offline'] = col.count_documents( {'status': 'offline'} )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc)
      return

    table = []
    table.append([ "Status", "Id", "Type", "Ext. Address", "Port", "Country", "Timezone"] )
    for c in cur:
      status = "DOWN"
      if c["status"] == "online": status = "UP"

      controller_type = 'unknown'
      try:
        controller_type = c["controller_type"]
      except:
        pass

      external_ip = '-'
      try:
        external_ip = c["external_ip"]
      except:
        pass

      ssh_port = '-'
      try:
        ssh_port = c["ssh_port"]
      except:
        pass

      row = [ status, c["id"], controller_type, external_ip, ssh_port ]
      try:
        country = c["geoip"]["country"]
        timezone = c["geoip"]["timezone"]
        row = row + [ country, timezone ]
      except:
        row = row + [ "Unknown", "Unknown" ]
      table.append( row )
    print( AsciiTable(table).table ) 
    print("Record count: %s  Online: %s  Offline: %s" % (count['total'], count['online'], count['offline']))
  # def

  # TODO
  def api_show_controller( self, id = None ):
    t = get_utc_time()
    query = { 'id': valid_id(id) }
    try:
      col = self.db_col('controllers')
      cur = col.find_one( query, projection={"_id": False})
      country = 'Unknown'
      timezone = 'Unknown'
      try:
        country = cur["geoip"]["country"]
        timezone = cur["geoip"]["timezone"]
      except:
        pass

      external_ip = ''
      try:
        external_ip = cur['external_ip']
      except:
        pass

      ssh_port = ''
      try:
        ssh_port = cur['ssh_port']
      except:
        pass

      data = {
        'country': country,
        'timezone': timezone, 
        'id': cur['id'],
        'external_ip': external_ip,
        'ssh_port': ssh_port,
        'status': cur['status']
      }
      args = {
        'template': MUS_SHOW_CONTROLLER,
        'data': data
      }
      print( chevron.render(**args) )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return
  # def

  def api_show_users(self):
    t = get_utc_time()
    count = {'total': 0}
    cur = None
    query = { 'node_type': { '$eq': 'admin' } }

    try:
      col = self.db_col('nodes')
      cur = col.find( query, projection={"_id": False}).sort("id")
      count['total'] = col.count_documents( query )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return

    if(not count['total']):
      msg = "No users found."
      print( msg )
      return

    table = []
    table.append([ 
      "Status", "Type", "Id", 
      "Description", "Key Algo", "Fingerprint", 
      "Last Update (UTC)"] )
    for c in cur:
      table.append( [ 
        c["status"], c["node_type"] , c["id"], 
        c["description"], c["ssh_key_algo"], c["ssh_fingerprint"], 
        c["updatedAt"] ] )
    # for
    print( AsciiTable(table).table) 
    print("Record count: %s" % (count['total'] ) )
  # def

##    ##  #######  ########  ########  ######  
###   ## ##     ## ##     ## ##       ##    ## 
####  ## ##     ## ##     ## ##       ##       
## ## ## ##     ## ##     ## ######    ######  
##  #### ##     ## ##     ## ##             ## 
##   ### ##     ## ##     ## ##       ##    ## 
##    ##  #######  ########  ########  ######  

  def api_show_nodes(self, status = None):
    if not status in ['all', 'online', 'offline']:
      raise Exception("Unknown status: %s" % status )

    t = get_utc_time()
    count = {'total': 0}
    cur = None

    # Query
    tags = None
    type = None
    sortby = "id"
    query = {}
    tags_array = []
    if tags:
      tags_array = tags.split(",")
      query = {"tags" : { "$in" : tags_array } }
    if type:
      query["node_type"] = { "$eq": type }
    if status != 'all':
      query["status"] = { "$eq": status }

    # Find
    try:
      col = self.db_col('nodes')
      cur = col.find( query, projection={"_id": False}).sort([
        ("%s" % sortby, ASCENDING),
        ("controller_id", ASCENDING),
        ("id", ASCENDING)
        ])
      count['total'] = col.count_documents( query )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return

    if(not count['total']):
      msg = "No nodes found."
      print( msg )
      return False

    table_header = [ 
      "Status", "Disabled", "Controller", "Node (IP Address)", 
      "Description", "SSH Key Algo", "SSH Client Version", 
      "Last Update (UTC)", "Last Update (Local)"] 
    table = []
    table.append( table_header )
    for c in cur:
      status = "DOWN"
      if c["status"] == "online":
        status = "UP"

      disabled = "Yes"
      if not c["disabled"]:
        disabled = ""

      cid = 'unknown'
      try:
        cid = c["controller_id"]
      except:
        pass

      peername = "unknown"
      try:
        peername = c["extra_info"]["peername"]
      except:
        pass
      nid = "%s (%s)" % (c["id"], peername)

      ssh_client = "unknown"
      try:
        ssh_client = c["extra_info"]["client_version"]
      except:
        pass

      table.append( [ 
        status, disabled, cid, nid, 
        c["description"], c["ssh_key_algo"], ssh_client,
        c["updatedAt"] ] )
    # for
    print( AsciiTable(table).table) 
    print("Record count: %s" % (count['total'] ) )
  # def

  def api_show_node(self, id = None):
    t = get_utc_time()
    query = { 'id': valid_id(id) }
    try:
      col = self.db_col('nodes')
      node = col.find_one( query, projection={"_id": False})

      data = {
        'id': node['id'],
        'status': node['status'],
        'updatedAt': utc2local(time=node['updatedAt']),
        'connectedAt':  utc2local(time=node['connectedAt']),
        # 'disconnectedAt': utc2local(time= node['disconnectedAt']),
        'createdAt':  utc2local(time=node['createdAt']),
        # extra_info 
        'external_ip': '-',
        'country': '-',
        'continent': '-',
        'timezone': '-',
        'client_version': '-',
        'send_cipher': '-',
        'recv_cipher': '-',
        'send_mac': '-',
        'recv_mac': '-',
        'description': '-',
        'product': '-',
        'serial': '-'
      }

      extra_info = {}
      try:
        node['extra_info']
        extra_info = {
        'external_ip': node['extra_info']['peername'],
        'country': node['extra_info']['geoip']['country'],
        'continent': node['extra_info']['geoip']['continent'],
        'timezone': node['extra_info']['geoip']['timezone'],
        'client_version': node['extra_info']['client_version'],
        'send_cipher':node['extra_info']['send_cipher'],
        'recv_cipher':node['extra_info']['recv_cipher'],
        'send_mac':node['extra_info']['send_mac'],
        'recv_mac':node['extra_info']['recv_mac']
        }
        data = {**data, **extra_info}
      except:
        pass
      args = { 'template': MUS_SHOW_NODE, 'data': data }
      print( chevron.render(**args) )
    except Exception as exc:
      raise exc
      self.log( level = 'error', message = "%s" % repr(exc) )
      return
  # def

  def api_node_delete(self, id = None ):
    t = get_utc_time()

    query = {'id': valid_id(id)}
    try:
      col = self.db_col('nodes')
      res = col.delete_one( query )

      if res.deleted_count:
        print("Node deleted")

    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return
  # def

  def api_node_enable( self, id = None ):
    t = get_utc_time()

    query = {'id': valid_id(id)}
    try:
      col = self.db_col('nodes')
      res = col.update_one( query, { '$set': {'disabled': False} }  )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return
  # def

  def api_node_disable( self, id = None ):
    query = {'id': valid_id(id)}
    try:
      col = self.db_col('nodes')
      res = col.update_one( query, { '$set': {'disabled': True} }  )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return
  # def


  def api_node_add(self, id = 'test', pubkey = None, force = False, desc = None, type = 'ssh'):
    valid_id(id)

    t = get_utc_time()
    public_key = None
    algo = None
    fingerprint = None
    try:
      public_key = asyncssh.import_public_key( pubkey )
      algo = public_key.get_algorithm()
      fingerprint = public_key.get_fingerprint()
    except Exception as exc:
      self.log( level = 'error', message = "Public key import failed: %s" % exc )
      return

    node = None
    query = { 'id': valid_id(id) }
    try:
      col = self.db_col('nodes')
      node = col.find_one( query, projection={"_id": False}  )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return

    # TODO: sanit
    description = ''
    if desc:
      description = desc
    update = {
      'id': id,
      'description': description,
      'node_type': type,
      'ssh_key_algo': algo,
      'ssh_pubkey': pubkey,
      'ssh_fingerprint': fingerprint,
      'disabled': False,
      'updatedAt': t,
      'connectedAt': None,
      'tenant_id': None,
      'tags': [],
      'group_id': None
    }

    if( node and not force ):
      print("Node %s already present use --force to update" % node)
      return

    if( not node ):
      update['createdAt'] = t
      update['status'] = 'new'

    try:
      res = col.update_one( query, { '$set': update }, upsert=True )
      # pp.pprint(dir(res))
      # print("Matched / Modified = %s / %s" % (res.matched_count, res.modified_count ) )
      # print(res.raw_result)
      # print("Node created")

      if res.modified_count:
        print("Node Updated")
      else:
        print("Node created")
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return
  # def

  # def api_add_ssh_node(self, id = 'test', pubkey = None, force = False, desc = None):
  #   ret = self.api_add_node(id = id, pubkey = pubkey, force = force, desc = desc, type = 'ssh')
  #   return ret
  # # def

#  def api_export_nodes(self, output = None ):
#    t = get_utc_time()
#    count = {'total': 0}
#    cur = None
#    query = {}
#    projection = { 
#      "_id": False,
#      "poller": False,
#      "extra_info": False
#    }
#    try:
#      col = self.db_col('nodes')
#      cur = col.find( query, projection ).sort("id")
#      count['total'] = col.count_documents( query )
#    except Exception as exc:
#      self.log( level = 'error', message = "Database error: %s" % exc )
#      return
#
#    export = []
#    for c in cur:
#      node = {
#        'id': c["id"],
#        'description': c["description"],
#        'disabled': c["disabled"],
#        'node_type': c["node_type"],
#        'ssh_fingerprint': c["ssh_fingerprint"],
#        'ssh_key_algo': c["ssh_key_algo"],
#        'ssh_pubkey': c["ssh_pubkey"],
#      }
#      try:
#        node['tags']= c["tags"]
#      except:
#        pass 
#      export.append( node )
#    # for
#
#    self.logger.info("%s Nodes found in the Database" % count['total'])
#    try:
#      # print(json.dumps(nodes, indent=2, sort_keys=True))
#      with open(output, 'w', encoding='utf-8') as out:
#        json.dump(export, out, ensure_ascii=False, indent=2, sort_keys=True)
#      self.log( level = 'info', message = "Nodes exported to JSON file: %s" % output)
#    except Exception as exc:
#      self.log( level = 'error', message = "Nodes export failed: %s" % output)
#  # def
#
#  def api_import_nodes(self, input = None ):
#    t = get_utc_time()
#    query = {}
#    try:
#      with open(input, 'r', encoding='utf-8') as inp:
#        data = json.load(inp)
#        bulk_update = []
#        for node in data:
#          query = { 'id': node['id'] }
#          update = node
#          update['createdAt'] = t
#          update['updatedAt'] = t
#          update['status'] = 'new'
#          bulk_update.append( UpdateOne( query, { '$set': update }, upsert=True ) )
#      # for
#      col = self.db_col('nodes')
#      res = col.bulk_write( bulk_update )
#      print("Matched: %s  Inserted: %s  Updated: %s  Upserted: %s" % ( res.matched_count, res.inserted_count, res.modified_count, res.upserted_count ) )
#    except Exception as exc:
#      self.log( level = 'error', message = "Nodes import failed: %s" % input )
#  # def
#
#  def api_node_description(self, id = None, desc = 'Description' ):
#    t = get_utc_time()
#    query = {'id': valid_id(id)}
#    node = None
#    try:
#      update = {
#        'id': id,
#        'description': desc,
#        'updatedAt': t,
#      }
#      col = self.db_col('nodes')
#      res = col.update_one( query, { '$set': update } )
#    except Exception as exc:
#      self.log( level = 'error', message = "Database error: %s" % exc )
#      return
#  # def
#  # def

  def api_port_alloc(self, id = None, service = 'ssh'):
    # Add Node Transaction
    valid_id(id)
    valid_id(service)
    port = None
    try:
      col_ports = self.db_col('ports')
      # col_nodes = self.db_col('nodes')
      next_empty = None
      # TODO: lock nodes
      with self.mongo_client.start_session() as session:
        with session.start_transaction():
          next_empty = {'id': port}
          if not port:
            next_empty = col_ports.find_one( { 'node_id': None }, session = session )
          query = { 'id': next_empty['id'] }
          update = {'node_id': id, 'service': service }
          col_ports.update_one( query, { '$set': update }, session = session)
        #
      #
      print("Allocated port for %s:%s is %s" % ( id, service, next_empty['id'] ) )
    except Exception as exc:
      self.log( level = 'error', message = "Database error: %s" % exc )
      return
  # def

  def api_port_dealloc(self, id = None, service = 'ssh'):
    # Add Node Transaction
    valid_id(id)
    valid_id(service)
    port = None
  # def

#  def api_test(self):
#    col = self.db_col('nodes')
#    pipeline = [ 
#      { '$lookup': { 'from': 'ports', 'localField': 'id', 'foreignField': 'node_id', 'as': 'ports' } },
#      { '$match': { 'ports.0' :{ '$exists': True } } },
#    # { '$reduce': { 'input': 'ports', 'in': { '$$this.service' : { '$eq': 'ssh '}  } }  },
#      { '$project': { '_id': False, 'id': True, 'ports': True } } ]
#    try:
#      res = col.aggregate(pipeline)
#      # pprint(list(res))
#      table = []
#      table.append([ "Id", "Ports" ] )
#      for c in res:
#        table.append( [ c["id"], c["ports"] ] )
#      # for
#      print( AsciiTable(table).table) 
#    except Exception as exc:
#      self.log( level = 'error', message = "Database error: %s" % exc )
#      return
#  # def
#
#  def _test(self):
#    col_ports = self.db_col('ports')
#    res = col_ports.find( { 'node_id': 'rpi' }, { '_id': False, 'id': True} )
#    ports = []
#    for r in res:
#      ports.append(r['id'])
#    print(res, ports )
#  # def

# class
