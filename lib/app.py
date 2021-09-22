
import os
import argparse
import logging
from dotenv import load_dotenv

## Application
class Application:
  """General Application Wrapper

  Parameters:
    __file (string): Parent file name
  """
  def __init__(self, __file = __file__):
    self.__basename__ = os.path.basename(__file)
    self.__dirname__ = os.path.dirname(__file)
    self.__abspath__ = os.path.abspath(__file)
    self.__absdir__ = os.path.dirname( self.__abspath__ )

    ## CLI Arguments
    self.arg_parser = argparse.ArgumentParser()
    self.add_arguments()
    self.arguments = self.arg_parser.parse_args()
    self.config = {}

    # Logger
    level = logging.INFO
    if self.arguments.debug:
      level = logging.DEBUG
    logging.basicConfig(
      level=level,
      format="[%s] " % (self.__basename__) + '%(asctime)s %(levelname)-8s %(message)s' + "\r",
      datefmt='%Y-%m-%d %H:%M:%S')
    self.logger = logging.getLogger(self.__basename__)

    ## Dotenv
    env = os.environ.get('DOTENV') or os.path.join(os.path.dirname(self.__basename__), ".env" )
    if( os.path.isfile(env) ):
      load_dotenv( dotenv_path=env )
      self.logger.info("Dotenv loaded from: %s", env)

    ## Signal Handlers
    # self.add_signal_handlers()
  # def

  def cleanup(self, signum, frame):
    self.logger.info("Cleanup...")
  # def

  def add_signal_handlers(self):
    # signal.signal(signal.SIGTERM, self.cleanup)
    # signal.signal(signal.SIGINT, self.cleanup)
    # signal.signal(signal.SIGHUP, self.cleanup)
    pass
  # def

  def add_arguments(self):
    self.arg_parser.add_argument('--debug', 
      default=False, 
      action='store_true', 
      help='Run in debug mode (verbose logging)')
  # def

# class
