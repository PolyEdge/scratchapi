import pip
try:
  import requests
except:
  pip.main(['install', 'requests'])
import shutil
shutil.copyfile('ScratchAPI', 'C:\\Python34\\Lib\\ScratchAPI.py')
