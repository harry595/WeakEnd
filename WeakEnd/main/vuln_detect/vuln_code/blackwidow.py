#!/usr/bin/python3
# blackwidow by @xer0dayz - Last Updated 20200717
# https://xerosecurity.com
#

from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests, sys, os, atexit, optparse
from http import cookies
requests.packages.urllib3.disable_warnings()

OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
COLOR1='\033[95m'
COLOR2='\033[96m'
RESET='\x1b[0m'

def readlinks (url):
  try:

    if len(cookies) > 2:
      headers = {'Cookie': cookies}
      r = requests.get(url, headers=headers, verify=False)
    else:
      r  = requests.get(url, verify=False)

    data = r.text
    soup = BeautifulSoup(data, "lxml")
    parsed_uri = urlparse(url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    domain = domain.split(':')[0]
  except Exception as ex:
    print(ex)

  urls = open( file_path+ "tmp/" + domain + "_" + port + "-urls.txt","w+")
  urls_saved = open(save_dir + domain + "_" + port + "-urls.txt","a")
  forms_saved = open(save_dir + domain + "_" + port + "-forms.txt","a")
  dynamic_saved = open(save_dir + domain + "_" + port + "-dynamic.txt","a")
  emails_saved = open(save_dir + domain + "_" + port + "-emails.txt","a")
  phones_saved = open(save_dir + domain + "_" + port + "-phones.txt","a")
  subdomains_saved = open(save_dir + domain + "_" + port + "-subdomains.txt","a")

  for form in soup.find_all('form'):
    forms_saved.write(url + "\n")

  # PARSE LINKS
  for link in soup.find_all('a'):
    # IF LINK IS NOT NULL
    if link.get('href') is not None:
      parsed_uri = urlparse(link.get('href'))
      linkdomain = '{uri.netloc}'.format(uri=parsed_uri)
      if (domain != linkdomain) and (linkdomain != "") and (domain in linkdomain):
        subdomains_saved.write(linkdomain + "\n")
      # IF LINK STARTS WITH HTTP
      if link.get('href')[:4] == "http":
        # SAME ORIGIN
        if domain in link.get('href'):
          # IF URL IS DYNAMIC
          if "?" in link.get('href'):
            urls.write(link.get('href') + "\n")
            urls_saved.write(link.get('href') + "\n")
            dynamic_saved.write(link.get('href') + "\n")
          else:
            urls.write(link.get('href') + "\n")
            urls_saved.write(link.get('href') + "\n")
      # IF URL IS DYNAMIC
      elif "?" in link.get('href'):
        urls.write(url + "/" + link.get('href') + "\n")
        urls_saved.write(url + "/" + link.get('href') + "\n")
        dynamic_saved.write(url + "/" + link.get('href') + "\n")
      # DOM BASED LINK
      #elif link.get('href')[:1] == "#":
      # TELEPHONE
      elif link.get('href')[:4] == "tel:":
        s = link.get('href')
        phonenum = s.split(':')[1]
        phones_saved.write(phonenum + "\n")
      # EMAIL
      elif link.get('href')[:7] == "mailto:":
        s = link.get('href')
        email = s.split(':')[1]
        emails_saved.write(email + "\n")
      # ELSE NORMAL LINK FOUND
      else:
        urls.write(url + "/" + link.get('href') + "\n")
        urls_saved.write(url + "/" + link.get('href') + "\n")

def readfile():
  filename =  file_path + "tmp/" + domain + "_" + port + "-urls.txt"
  with open(filename) as f:
    urls = f.read().splitlines()
    for url in urls:
      try:
        readlinks(url)
      except Exception as ex:
        print(ex)

globalURL = "globalBadness"
if len(sys.argv) < 2:
  print ("You need to specify a URL to scan. Use --help for all options.")
  quit()
else:
  parser = optparse.OptionParser()
  parser.add_option('-u', '--url',
                    action="store", dest="url",
                    help="Full URL to spider", default="")

  parser.add_option('-d', '--domain',
                    action="store", dest="domain",
                    help="Domain name to spider", default="")

  parser.add_option('-c', '--cookie',
                    action="store", dest="cookie",
                    help="Cookies to send", default="")

  parser.add_option('-l', '--level',
                    action="store", dest="level",
                    help="Level of depth to traverse", default="2")

  parser.add_option('-s', '--scan',
                    action="store", dest="scan",
                    help="Scan all dynamic URL's found", default="n")

  parser.add_option('-p', '--port',
                    action="store", dest="port",
                    help="Port for the URL", default="80")

  parser.add_option('-v', '--verbose',
                    action="store", dest="verbose",
                    help="Set verbose mode ON", default="y")

  options, args = parser.parse_args()
  target = str(options.url)
  domain = str(options.domain)
  cookies = str(options.cookie)
  max_depth = str(options.level)
  scan = str(options.scan)
  port = str(options.port)
  verbose = str(options.verbose)
  ans = scan
  level = 1

  # using a domain and a port or a URL?
  if ":" not in target:

    if len(str(target)) > 6:
      url = target + ":" + port #big change here

    else:
      url = "http://" + str(domain) + ":" + port

    if len(str(domain)) > 4:
      target = "http://" + domain + ":" + port
    else:
      urlparse(target)
      parsed_uri = urlparse(target)
      domain = '{uri.netloc}'.format(uri=parsed_uri)

  else:
    url = target
    globalURL = target
    parsed_uri = urlparse(target)
    domainWithPort = '{uri.netloc}'.format(uri=parsed_uri)
    domain = domainWithPort.split(':')[0]
    if (len(target.split(':')) > 2):
      portWithPossiblePath = target.split(':')[2]
      port = portWithPossiblePath.split('/')[0]
    else:
      port = port

  file_path = os.path.dirname(os.path.realpath(__file__)) + '/dirscanning/'
  save_dir = file_path + domain + "_" + port + "/"
  try:
      if not os.path.exists(save_dir):
          os.makedirs(save_dir)
  except OSError:
      print ('Error: Creating directory. ' +  save_dir)


  # FILE INIT
  urls_file =  file_path + "tmp/" + domain + "_" + port + "-urls.txt"
  urls_saved_file = save_dir + domain + "_" + port + "-urls.txt"
  forms_saved_file = save_dir + domain + "_" + port + "-forms.txt"
  subdomain_file = save_dir + domain + "_" + port + "-subdomains.txt"
  emails_file = save_dir + domain + "_" + port + "-emails.txt"
  phones_file = save_dir + domain + "_" + port + "-phones.txt"
  urls = open(urls_file,"w+")
  urls.close()
  urls_saved = open(urls_saved_file,"w+")
  urls_saved.close()
  forms_saved = open(forms_saved_file,"w+")
  forms_saved.close()
  subdomains = open(subdomain_file,"w+")
  subdomains.close()
  emails = open(emails_file,"w+")
  emails.close()
  phones = open(phones_file,"w+")
  phones.close()


  try:
    readlinks(url)
  except Exception as ex:
    print(ex)

  while (int(level) <= int(max_depth)):
    level = level+1
    if (int(level) <= int(max_depth)):
      try:
        readfile()
      except Exception as ex:
        print(ex)
    else:
      break