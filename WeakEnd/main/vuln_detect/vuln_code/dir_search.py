
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests, sys, os, atexit, optparse
from http import cookies
requests.packages.urllib3.disable_warnings()
-
#black widow 작업중

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
        if ':' in  linkdomain:
          linkdomain = linkdomain.split(':')[0]
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
            print (link.get('href'))
            urls.write(link.get('href') + "\n")
            urls_saved.write(link.get('href') + "\n")
      elif "?" in link.get('href'):
        urls.write(url + "/" + link.get('href') + "\n")
        urls_saved.write(url + "/" + link.get('href') + "\n")
        dynamic_saved.write(url + "/" + link.get('href') + "\n")

def readfile():
  filename = file_path + "tmp/" + domain + "_" + port + "-urls.txt"
  with open(filename) as f:
    urls = f.read().splitlines()
    for url in urls:
      try:
        readlinks(url)
      except Exception as ex:
        print(ex)

def exit_handler():
  sublist_txt = open(save_dir + domain + "_" + port + "-subdomains.txt", "r")
  dynamic_txt= open(save_dir + domain + "_" + port + '-dynamic.txt', "a")
  forms_txt = open(save_dir + domain + "_" + port + '-forms.txt', "a")
  while True:
    subdomain = sublist_txt.readline().rstrip('\n')
    if not subdomain:
      break
    try:
      subdynamic_txt = open(save_dir + subdomain + "_" + port + '-dynamic.txt', "r")
      subforms_txt= open(save_dir + subdomain + "_" + port + '-forms.txt', "r")
      while True:
        dynamic = subdynamic_txt.readline().rstrip('\n')
        if not dynamic:
          break
        dynamic_txt.write(dynamic+'\n')
      subdynamic_txt.close()
      while True:
        forms = subforms_txt.readline().rstrip('\n')
        if not forms:
          break
        forms_txt.write(forms+'\n')
      subforms_txt.close()
    except: FileNotFoundError
  sublist_txt.close()
  dynamic_txt.close()
  forms_txt.close()
  pass

####################################메인######################

globalURL = "globalBadness"
if len(sys.argv) < 2:
  print ("You need to specify a URL to scan. Use --help for all options.")
  quit()
else:   #####입력 파싱
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
  parser.add_option('-p', '--port',
                    action="store", dest="port",
                    help="Port for the URL", default="80")
  options, args = parser.parse_args()
  print("!@#")
  print(options)
  print(args)
  print("!@#")
  target = str(options.url)
  domain = str(options.domain)
  cookies = str(options.cookie)
  max_depth = str(options.level)
  port = str(options.port)
  level = 1
  if ":" not in target:
    if len(str(target)) > 6:                          #####url로 입력
      url = target + ":" + port #big change here                  ##
                                                                  ##
    else:                                                         ##
      url = "http://" + str(domain) + ":" + port      ##############
    if len(str(domain)) > 4:                          ####domain 입력
      target = "http://" + domain + ":" + port                    ##
    else:                                                         ##
      print (target)                                              ##
      urlparse(target)                                            ##
      parsed_uri = urlparse(target)                               ##
      domain = '{uri.netloc}'.format(uri=parsed_uri)  ##############
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
  atexit.register(exit_handler)
  # FILE INIT
  urls_file =  file_path + "tmp/" + domain + "_" + port + "-urls.txt"
  urls_saved_file = save_dir + domain + "_" + port + "-urls.txt"
  forms_saved_file = save_dir + domain + "_" + port + "-forms.txt"
  subdomain_file = save_dir + domain + "_" + port + "-subdomains.txt"
  urls = open(urls_file,"w+")
  urls.close()
  urls_saved = open(urls_saved_file,"w+")
  urls_saved.close()
  forms_saved = open(forms_saved_file,"w+")
  forms_saved.close()
  subdomains = open(subdomain_file,"w+")
  subdomains.close()
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
