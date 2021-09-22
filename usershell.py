import os, sys
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

  @shell(prompt="SSHNOC [%s]> " % cli.config['mongo_uri_masked'], hist_file = hist_file )
  def servercli():
    pass


  ## GENERAL
  @servercli.command()
  def restart():
    print("Restarting Server CLI ...")
    os.execv( sys.executable, ['python'] + _saved_argv )
  # def

  @servercli.command()
  def test():
    cli.api_test()


  ## MAIN
  servercli()

if __name__ == '__main__':
  servershell()
