import os
import sys
from click.core import _complete_visible_commands
# https://click.palletsprojects.com/en/8.0.x/complex/
from click_shell import shell
import click

import jwt
import json
# import asyncssh

# https://pymongo.readthedocs.io/en/stable/examples/bulk.html
# from pymongo import UpdateOne

# https://robpol86.github.io/terminaltables/
# from terminaltables import AsciiTable

# https://github.com/noahmorrison/chevron
import chevron

from pprint import PrettyPrinter
pprint = PrettyPrinter(indent=4).pprint

from lib.controller_api import ControllerWithAPI #, MONGO_URI, MONGO_DB
from lib.util import valid_id, valid_port, valid_secret
# from lib.util import get_utc_time


######## ######## ##     ## ########  ##          ###    ######## ########  ######  
   ##    ##       ###   ### ##     ## ##         ## ##      ##    ##       ##    ## 
   ##    ##       #### #### ##     ## ##        ##   ##     ##    ##       ##       
   ##    ######   ## ### ## ########  ##       ##     ##    ##    ######    ######  
   ##    ##       ##     ## ##        ##       #########    ##    ##             ## 
   ##    ##       ##     ## ##        ##       ##     ##    ##    ##       ##    ## 
   ##    ######## ##     ## ##        ######## ##     ##    ##    ########  ######  

WELCOME = """
Interactive SSHNOC Server Shell
-------------------------------
Type help for available commands
"""

PROMPT = "SSHNOC ADMIN"

def servershell():
  cli = ControllerWithAPI( __file__ )
  pid = os.getpid()

  cli.init( controller_type = 'shell', id = "adminshell-%s" % pid )

  _saved_argv = sys.argv
  sys.argv = [sys.argv[0]]

  args = { 'template': WELCOME, 'data': {} }
  print( chevron.render(**args) )
  if cli.arguments.debug:
    print("Debug is ON\n")

  hist_file = os.path.join(cli.__absdir__, '.adminshell.history')

  @shell(prompt="%s [%s]> " % ( PROMPT, cli.config['mongo_uri_masked'] ), hist_file = hist_file )
  def clishell():
    pass

 ######   #######  ##     ## ##     ##    ###    ##    ## ########   ######  
##    ## ##     ## ###   ### ###   ###   ## ##   ###   ## ##     ## ##    ## 
##       ##     ## #### #### #### ####  ##   ##  ####  ## ##     ## ##       
##       ##     ## ## ### ## ## ### ## ##     ## ## ## ## ##     ##  ######  
##       ##     ## ##     ## ##     ## ######### ##  #### ##     ##       ## 
##    ## ##     ## ##     ## ##     ## ##     ## ##   ### ##     ## ##    ## 
 ######   #######  ##     ## ##     ## ##     ## ##    ## ########   ######  

  @clishell.command()
  def restart():
    print("Restarting CLI ...")
    os.execv( sys.executable, ['python'] + _saved_argv )
  # def

  # TODO: --json --table --csv
  # show
  @clishell.group()
  def show():
    pass

  # show events
  @show.command(help = "Show latest controller events saved to the database")
  @click.option('--limit', help = 'Limit the number of lines (default = 50)', default=50)
  @click.option('--node', help = 'Filter for Node Id (default = all)', default='all')
  @click.option('--controller', help = 'Filter for Controller Id (default = all)', default='all')
  def events(limit = None, node = None, controller = None):
    cli.api_show_events(limit = limit, node_id = node, controller_id = controller)
  # def

  # show controllers
  @show.command(help = "Show controller list")
  @click.argument('status', default='all')
  def controllers(type = None, status = None):
    cli.api_show_controllers(type = type, status = status)
  # def

  # show nodes
  @show.command( help = "Show node list")
  @click.argument('status', default='all')
  def nodes(status = None):
    cli.api_show_nodes(status = status )
  # def

  # show node ID
  @show.command( help = "Show node details")
  @click.argument('id')
  def node(id = None):
    cli.api_show_node( id = id )

  # show controller ID
  @show.command(help = "Show controller details")
  @click.argument('id')
  def controller( id = None):
    cli.api_show_controller( id = id )
  # def

  @show.command(help = "Show user list")
  def users():
    cli.api_show_users()
  # def

  # node commands
  @clishell.group()
  def node():
    pass

  # node add ...
  @node.command( help = "Add a new node or update")
  @click.argument('type', default='ssh')
  @click.option('--id', required=True)
  @click.option('--pubkey', required=True)
  @click.option('--force', is_flag=True, default=False)
  @click.option('--desc')
  def add(type = None, id = None, pubkey = None, force = False, desc = None ):
    cli.api_node_add(id = id, pubkey = pubkey, force = force, desc = desc, type = type )

  # node delete ID
  @node.command( help = "Delete a node")
  @click.argument('id')
  @click.option('--yesiwant2delete', required=True, is_flag=True, default=False)
  def delete(id = None, yesiwant2delete = None ):
    if( yesiwant2delete ):
      cli.api_node_delete(id = id)
    else:
      print("Use --yesiwant2delete flag in order to acknowledge node delete")

  # node enable ID
  @node.command( help = "Enable a node")
  @click.argument('id')
  def enable(id = None):
    cli.api_node_enable(id = id)

  # node disable ID
  @node.command( help = "Disable a node")
  @click.argument('id')
  def disable(id = None):
    cli.api_node_disable(id = id)


  # port commands
  @clishell.group()
  def port():
    pass

  # port alloc / dealloc
  @port.command()
  @click.option('--id', required=True, help = "Node Id" )
  @click.option('--service', required=True, help = "Service short name eg. ssh, http ..." )
  def alloc(id,service):
    cli.api_port_alloc(id=id,service=service)
  # def

# TODO: description and tagging
#
#  @clishell.command()
#  @click.option('--id', required=True, help = "Node Id" )
#  @click.option('--desc', required=True, help = "Description" )
#  def node_description(id,desc):
#    cli.api_node_description(id=id,desc=desc)
#  # def


  # @node.command( help = "Enable node")
  # @click.argument('id')
  # def enable(id = None):
  #   print(id)
  # @node.command( help = "Disable node")
  # @click.argument('id')
  # def disable(id = None):
  #   print(id)

  # TODO: port alloc / dealloc
#  @clishell.command()
#  @click.option('--id', required=True, help = "Node Id" )
#  @click.option('--service', required=True, help = "Service short name eg. ssh, http ..." )
#  def allocate_port(id,service):
#    cli.api_allocate_port(id=id,service=service)
#  # def

  # TODO: status, syscheck, export import
#  @clishell.command()
#  @click.option('--data', required=True, default="nodes.json")
#  def export_nodes(data):
#    cli.api_export_nodes(output=data)
#  # def
#
#  @clishell.command()
#  @click.option('--data', required=True, default="nodes.json")
#  def import_nodes(data):
#    cli.api_import_nodes(input=data)
#  # def


  ## MAIN
  clishell()

if __name__ == '__main__':
  servershell()
