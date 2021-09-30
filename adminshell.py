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
  cli.init( controller_type = 'shell' )

  _saved_argv = sys.argv
  sys.argv = [sys.argv[0]]

  args = { 'template': WELCOME, 'data': {} }
  print( chevron.render(**args) )
  if cli.arguments.debug:
    print("Debug is ON\n")

  hist_file = os.path.join(cli.__absdir__, '.click-history')

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

  # show nodes
  @show.command( help = "Show node list")
  @click.argument('status', default='all')
  def nodes(tags = None, type = None, status = None, sortby = "id"):
    if not status in ['all', 'online', 'offline']:
      raise Exception("Unknown status: %s" % status )
    cli.api_nodes(tags = tags, type = type, status = status, sortby = sortby )
  # def

  # TODO: show node ID
  @show.command( help = "Show node details")
  @click.argument('id')
  def node(id = None):
    cli.api_node( id = id )

  # show controllers
  @show.command(help = "Show controller list")
  @click.argument('status', default='all')
  def controllers(type = None, status = None):
    if not status in ['all', 'online', 'offline']:
      raise Exception("Unknown status: %s" % status )
    cli.api_controllers(type = type, status = status)
  # def

  # TODO: show controller ID
  @show.command(help = "Show controller details")
  @click.argument('id')
  def controller( id = None):
    cli.api_controller( id = id )
  # def

  @show.command(help = "Show user list")
  def users():
    cli.api_users()
  # def

  @show.command(help = "Show events")
  @click.option('--limit', help = 'Limit the number of lines', default=50)
  @click.option('--node', help = 'Filter option for status', default='all')
  @click.option('--controller', help = 'Filter option for status', default='all')
  def events(limit = None, node = None, controller = None):
    cli.api_events(limit, node, controller)
  # def

  # node commands
  @clishell.group()
  def node():
    pass

  @node.command( help = "Add a new node or update")
  @click.argument('type', default='ssh')
  @click.option('--id', required=True)
  @click.option('--pubkey', required=True)
  @click.option('--force', is_flag=True, default=False)
  @click.option('--desc')
  def add(type = None, id = None, pubkey = None, force = False, desc = None ):
    cli.api_add_node(id = id, pubkey = pubkey, force = force, desc = desc, type = type )

  @node.command( help = "Delete a node")
  @click.argument('id')
  @click.option('--yesiwant2delete', required=True, is_flag=True, default=False)
  def delete(id = None, yesiwant2delete = None ):
    if( yesiwant2delete ):
      cli.api_delete_node(id = id)
    else:
      print("Use --yesiwant2delete flag in order to acknowledge node delete")

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
