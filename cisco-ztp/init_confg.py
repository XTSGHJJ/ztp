import cli
import os

config = os.popen('curl -X POST http://192.168.1.7/devcfg/'+'test')
cli.configurep(config)