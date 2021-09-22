import os
import sys
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

  @shell(prompt="SSHNOC ADMIN [%s]> " % cli.config['mongo_uri_masked'], hist_file = hist_file )
  def servercli():
    pass


  ## GENERAL
  @servercli.command()
  def restart():
    print("Restarting Server CLI ...")
    os.execv( sys.executable, ['python'] + _saved_argv )
  # def


  ## JWT
  @servercli.command()
  @click.option('--secret', help = 'JWT Secret' )
  @click.option('--payload', help = 'Payload Data')
  def encode_jwt( secret = None, payload = None):
    encoded_jwt = jwt.encode( json.loads(payload), secret, algorithm="HS256")
    click.echo( 'Encoded payload:' )
    click.echo( encoded_jwt )


  ## CONTROLLERS
  @servercli.command()
  @click.option('--type', help = 'Filter option for type' )
  @click.option('--status', help = 'Filter option for status')
  def controllers(type = None, status = None):
    cli.api_controllers(type = type, status = status)
  # def

  @servercli.command()
  @click.option('--id', default="test", required=True, help = 'Controller Id')
  def controller( id = None):
    cli.api_controller( id = id )
  # def

  ## USERS
  @servercli.command()
  def users():
    cli.api_users()
  # def


  ## NODES
  @servercli.command()
  @click.option('--tags')
  @click.option('--type', help = 'Filter option for type' )
  @click.option('--status', help = 'Filter option for status')
  @click.option('--sortby', help = 'Filter option for sort')
  def nodes(tags = None, type = 'ssh', status = None, sortby = "id"):
    cli.api_nodes(tags = tags, type = type, status = status, sortby = sortby )
  # def

  @servercli.command()
  @click.option('--id', default="test", required=True, help = 'Node Id' )
  def node(id = None):
    cli.api_node( id = id )
  # def

  @servercli.command()
  @click.option('--tags')
  def online(tags = None ):
    cli.api_nodes(tags = tags, type = 'ssh', status = 'online' )
  # def


  @servercli.command()
  @click.option('--id', default="test", required=True, help = 'Node Id' )
  @click.option('--pubkey', required=True)
  @click.option('--force', is_flag=True, default=False)
  @click.option('--desc')
  def add_ssh_node(id, pubkey, force, desc):
    cli.api_add_ssh_node(id = id, pubkey = pubkey, force = force, desc = desc )
  # def

  @servercli.command()
  @click.option('--id', default="test", required=True )
  @click.option('--pubkey', required=True)
  @click.option('--force', is_flag=True, default=False)
  @click.option('--desc')
  @click.option('--type', default="ssh", required=True )
  def add_node(id, pubkey, force, desc, type ):
    cli.api_add_node(id = id, pubkey = pubkey, force = force, desc = desc, type = type )
  # def

  @servercli.command()
  @click.option('--data', required=True, default="nodes.json")
  def export_nodes(data):
    cli.api_export_nodes(output=data)
  # def

  @servercli.command()
  @click.option('--data', required=True, default="nodes.json")
  def import_nodes(data):
    cli.api_import_nodes(input=data)
  # def

  @servercli.command()
  @click.option('--id', required=True, help = "Node Id" )
  @click.option('--service', required=True, help = "Service short name eg. ssh, http ..." )
  def allocate_port(id,service):
    cli.api_allocate_port(id=id,service=service)
  # def

  @servercli.command()
  @click.option('--id', required=True, help = "Node Id" )
  @click.option('--desc', required=True, help = "Description" )
  def node_description(id,desc):
    cli.api_node_description(id=id,desc=desc)
  # def

  @servercli.command()
  def test():
    cli.api_test()


  ## MAIN
  servercli()

if __name__ == '__main__':
  servershell()
