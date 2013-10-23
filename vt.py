#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Built on (Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity)
# Updated with full VT APIv2 functions by Andriy Brukhovetskyy (DoomedRaven)
# No Licence or warranty expressed or implied, use however you wish! 
# For more information look at https://www.virustotal.com/es/documentation/public-api

import os
import glob
import time
import hashlib
import postfile
from pprint import pprint
from operator import methodcaller
import json, urllib, urllib2, argparse, hashlib, re, sys

def print_results(jdata, undetected_downloaded_samples, detected_communicated,\
                  undetected_communicated_samples, detected_urls):
    
        
    if undetected_downloaded_samples:
          print '\n[+] Latest undetected files that were downloaded from this domain/ip'
          for json_part in sorted(jdata['undetected_downloaded_samples'], key=methodcaller('get', 'date'), reverse=True):
            print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                      '\t','Sha256 :', json_part['sha256']
    
    if detected_communicated:
        print '\n[+] Latest detected files that communicate with this domain/ip'
        for json_part in sorted(jdata['detected_communicating_samples'] , key=methodcaller('get', 'scan_date'), reverse=True):
          print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                      '\t','Sha256 :', json_part['sha256']
    
    if undetected_communicated_samples:
        print '\n[+] Latest undetected files that communicate with this domain/ip'
        for json_part in sorted(jdata['undetected_communicating_samples'], key=methodcaller('get', 'date'), reverse=True):
          print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                    '\t','Sha256 :', json_part['sha256']
    if detected_urls:
          print '\n[+] Latest detected URLs'
          for row in sorted(jdata['detected_urls'], key=methodcaller('get', 'scan_date'), reverse=True):
            print '\t','{positives}/{total}'.format(positives = row['positives'],total = row['total']), '\t' ,'    --    ' if row['scan_date'] == None\
                                                                                           else row['scan_date'].split(' ')[0],'\t', row['url']

def jsondump(jdata, md5):
      jsondumpfile = open('VTDL_{md5}.json'.format(md5 = md5), 'w')
      pprint(jdata, jsondumpfile)
      jsondumpfile.close()
      print '\n\tJSON Written to File -- VTDL_{md5}.json'.format(md5 = md5)
 
class vtAPI():
    
    def __init__(self):
      
        #self.api = '<--------------PUBLIC-API-KEY-GOES-HERE----->'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,hash_report):
        
        param  = {'resource':hash_report,'apikey':self.api}
        url    = self.base + 'file/report'
        data   = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata  =  json.loads(result.read())
        return jdata
    
    def rescan(self,hash_re):
        
        if len(hash_re) == 1:
            hash_re = hash_re
        elif isinstance(hash_re, basestring):
            hash_re = [hash_re]
        elif len(hash_re) > 25 and not isinstance(hash_re, basestring):
            print '[-] To many urls for scanning, MAX 25'
            sys.exit()
        else:
            hash_re = ', '.join(map(lambda hash_part: hash_part, hash_re))
        
        for hash_part in hash_re:
            param  = {'resource':hash_part,'apikey':self.api}
            url    = self.base + 'file/rescan'
            data   = urllib.urlencode(param)
            result = urllib2.urlopen(url,data)
            jdata  =  json.loads(result.read())
            
            if isinstance(jdata, list):
                for jdata_part in jdata:
                  print '[+] Check rescan result with sha256 in few minuts:','\n\tSHA256 :',jdata['sha256']
                  print '\tPermanent link', jdata['permalink']
            else:
              print '[+] Check rescan result with sha256 in few minuts:','\n\tSHA256 :',jdata['sha256']
              print '\tPermanent link', jdata['permalink']
    
    def fileScan(self,files):

        if len(files) == 1:
            files = glob.glob('{files}'.format(files=files[0]))
        elif isinstance(files, basestring):
            files = glob.glob('{files}'.format(files=files))

        host  = 'www.virustotal.com'
        param = [('apikey',self.api)]
        url   = self.base + 'file/scan'

        for submit_file in files:
            
            if os.path.isfile(submit_file):
              print 'Submiting file: {filename}'.format(filename = submit_file)

              file_upload = open(submit_file, 'rb').read()
              files  = [("file", submit_file, file_upload)]
              result = postfile.post_multipart(host, url, param, files)
              jdata  =  json.loads(result)
            
              print '\n\tResults for MD5:    ',jdata['md5']
              print '\tResults for SHA1:   ',jdata['sha1']
              print '\tResults for SHA256: ',jdata['sha256']
            
              print '\n\tStatus        ',jdata['verbose_msg']
              print '\tPermament link',jdata['permalink'],'\n'
            
              if len(files) != 1:
                time.sleep(5)

        
    def url_scan_and_report(self, urls, key, verbose, dump=False, add_to_scan='0'):
        
        md5 = ''
        
        if len(urls) == 1:
            url_upload = urls[0]
        elif isinstance(urls, basestring):
            url_upload = urls  
        elif len(urls) > 4 and not isinstance(urls, basestring):
            print '[-] To many urls for scanning, MAX 4'
            sys.exit()
        else:
            if key == 'scan':
              url_upload = '\n'.join(map(lambda url: url, urls))
            elif key == 'report':
              url_upload = ', '.join(map(lambda url: url, urls))
            
        if key == 'scan':
          print 'Submitting url(s) for analysis: \n\t{url}'.format(url = url_upload.replace('\n','\n\t'))
          param = {'url':url_upload,'apikey':self.api}
          url   = self.base + 'url/scan'
          
        elif key == 'report':
          print 'Searching for url(s) report: \n\t{url}'.format(url = url_upload.replace(', ','\n\t'))
          param = {'resource':url_upload,'apikey':self.api, 'scan':add_to_scan}
          url   = self.base + 'url/report'  
        
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata  =  json.loads(result.read())

        if isinstance(jdata, list):
          for jdata_part in jdata:

            if dump == True:
              md5 = hashlib.md5(jdata_part['url']).hexdigest()

            if key == 'report':
                  url_report = True
                  parse_report(jdata_part, md5, verbose, dump, url_report)
            
            elif key == 'scan':
              print '\n\tStatus',jdata_part['verbose_msg'], '\t', jdata_part['url']
              print '\tPermanent link:', jdata_part['permalink']

        else:
          if dump == True:
            md5 = hashlib.md5(jdata["url"]).hexdigest()
          
          if key == 'report':
                  url_report = True
                  parse_report(jdata, md5, verbose, dump, url_report)
                  
          elif key == 'scan':
              print '\n\tStatus',jdata['verbose_msg'], '\t', jdata['url']
              print '\tPermanent link:', jdata['permalink']
        
    def getIP(self, ip, dump=False, detected_urls=False, detected_downloaded_samples=False, undetected_downloaded_samples=False,\
                                                         detected_communicated=False, undetected_communicated=False):
        param  = {'ip':ip,'apikey':self.api}
        url    = self.base + 'ip-address/report'
        data   = urllib.urlencode(param)
        result = urllib.urlopen('{url}?{data}'.format(url = url, data = data))
        jdata  =  json.loads(result.read())
        
        if dump == True:
            md5 = hashlib.md5(ip).hexdigest()
            jsondump(jdata, md5)
        
        if jdata['response_code'] == 1:
            print '\nStatus:         ', jdata['verbose_msg'],'\n'
        
        
            if detected_downloaded_samples:
              print '\n[+] Latest detected files that were downloaded from this domain/ip'
              for json_part in sorted(jdata['detected_downloaded_samples'], key=methodcaller('get', 'date'), reverse=True):
                print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                      '\t','Sha256 :', json_part['sha256']
            
            print_results(jdata, undetected_downloaded_samples, detected_communicated, undetected_communicated, detected_urls)
            
            
            
            print '\n[+] Lastest domain resolved'
            for data in  sorted(jdata['resolutions'], key=methodcaller('get', 'last_resolved'), reverse=True):
              print '\t','    --    ' if data['last_resolved'] == None else data['last_resolved'].split(" ")[0],'\t',data['hostname']
        
        else:
            print '\n[-] Not Found in VT\n'
           
    def getDomain(self, domain, dump, trendmicro=False, detected_urls=False, undetected_downloaded_samples=False, alexa_domain_info=False,\
                  wot_domain_info=False, websense_threatseeker=False, bitdefender=False, webutation_domain=False,\
                                         detected_communicated=False, undetected_communicated=False, pcaps=False):
        
        """
        Get domain last scan, detected urls and resolved IPs
        """
        param  = {'domain':domain,'apikey':self.api}
        url    = self.base + "domain/report"
        data   = urllib.urlencode(param)
        result = urllib.urlopen("{url}?{data}".format(url = url, data = data))
        jdata  =  json.loads(result.read())
        
        if jdata['response_code'] == 1:
            
            if dump == True:
                md5 = hashlib.md5(domain).hexdigest()
                jsondump(jdata, md5)
                
            print '\nStatus:         ', jdata['verbose_msg']
            
            if trendmicro:
                print '\n[+] TrendMicro category'
                print '\t',jdata['TrendMicro category']
            
            if websense_threatseeker:
                print '\n[+] Websense ThreatSeeker category'
                print '\t', jdata['Websense ThreatSeeker category']
            
            if bitdefender:
                print '\n[+] BitDefender category'
                print '\t', jdata["BitDefender category"]
            
            if alexa_domain_info:
              print '\n[+] Alexa domain info'
              print '\t', jdata['Alexa domain info']
            
            if wot_domain_info:
              print '\n[+] WOT domain info'
              for jdata_part in jdata['WOT domain info']:
                print '\t',jdata_part,'\t' if len(jdata_part) < 7 else '','\t' if len(jdata_part) < 14 else '','\t',jdata['WOT domain info'][jdata_part]
              
            if webutation_domain:
              print "\n[+] Webutation"
              for jdata_part in jdata['Webutation domain info']:
                print '\t', jdata_part,'\t' if len(jdata_part) < 7 else '','\t' if len(jdata_part) < 14 else '','\t',jdata['Webutation domain info'][jdata_part]
              
            print_results(jdata, undetected_downloaded_samples, detected_communicated, undetected_communicated, detected_urls)
            
            if pcaps:
              print '\n[+] Pcaps'
              for jdata_part in jdata['pcaps']:
                print '\t',jdata_part
             
            print '\n[+] Passive DNS replication'
            for row in sorted(jdata['resolutions'], key=methodcaller('get', 'last_resolved'), reverse=True):
              print "\t","    --    " if row["last_resolved"] == None else row["last_resolved"].split(" ")[0], '\t', row['ip_address']
        
        else:
            print '\n[-] Not Found in VT\n'
              
    def addComment(self, hash_co, comment):
        param  = {'resource':md5,'comment':comment,'apikey':self.api}
        url    = self.base + "comments/put"
        data   = urllib.urlencode(param)
        result = urllib2.Request(url, data)
        jdata  =  json.loads(result.read())
        
        print '\nStatus:         ', jdata['verbose_msg'],'\n'
    
def parse_report(jdata, hash_report, verbose, dump, url_report = False):
  if jdata['response_code'] != 1:
    print '\n[-] Not Found in VT\n'
    sys.exit()
  
  print '\n\tScanned on:          ',jdata['scan_date']
  print '\tDetected by:         ',jdata['positives'],'/',jdata['total']
   
  if not url_report:
    print '\n\tSophos Detection:    ',jdata['scans']['Sophos']['result']
    print '\tKaspersky Detection: ',jdata['scans']['Kaspersky']['result']
    print '\tTrendMicro Detection:',jdata['scans']['TrendMicro']['result']

    print '\n\tResults for MD5:    ',jdata['md5']
    print '\tResults for SHA1:   ',jdata['sha1']
    print '\tResults for SHA256: ',jdata['sha256']
  
  else:
    print '\n\tStatus      :',jdata['verbose_msg']
    print '\tScanned url : {url}'.format(url = jdata['url'])

  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in jdata['scans']:
     
     if not url_report:
       print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',jdata['scans'][x]['detected'], '\t',jdata['scans'][x]['result'] 
     
     else:
       print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 15 else '', '\t' if len(x) < 20 else '','\t',\
       jdata['scans'][x]['detected'],'\t', jdata['scans'][x]['result'], '\n\t\t\t{detail}'.format(detail = jdata['scans'][x]['detail'])\
                                                                                                   if jdata['scans'][x].get('detail',0) else ''
  if dump == True:
    jsondump(jdata, hash_report)
    
  print "\n\tPermanent Link:     ",jdata['permalink'],"\n"

def main():
  opt=argparse.ArgumentParser('value',description='Scan/Search/ReScan')

  opt.add_argument('value', nargs='*', help='Enter the Hash, Path to File or Url')
  opt.add_argument('-f', '--file-scan',   action='store_true', dest='files',      help='File(s) scan, support linux name wildcard, example: /home/user/*malware*, sleeping 5 seconds, between uploads, by default work over HTTPS')
  opt.add_argument('-us', '--url-scan',   action='store_true',                    help='Url scan, support space separated list, Max 4 urls')
  opt.add_argument('-ur', '--url-report', action='store_true',                    help='Url(s) report, support space separated list, Max 4 urls, you can use --url-report --url-scan options for analysing url(s) if they are not in VT data base')
  
  opt.add_argument('-r', '--rescan',      action='store_true',                    help='Force Rescan with Current A/V Definitions by MD5/SHA1/SHA256, support space separated list, MAX 25 hashes')
  opt.add_argument('-d', '--domain-info', action='store_true', dest='domain',     help='Retrieving domain reports')
  opt.add_argument('-i', '--ip-info',     action='store_true', dest='ip',         help='Retrieving IP address reports')
  opt.add_argument('-s', '--search',      action='store_true',                    help='Search VirusTotal by MD5/SHA1/SHA256')
  opt.add_argument('-c', '--add-comment', action='store_true',                    help='Add comment to analysis report, first hash and then your comment, supported hashes MD5/SHA1/SHA256')
  opt.add_argument('-v', '--verbose',     action='store_true', dest='verbose',    help='Turn on verbosity of VT reports')
  opt.add_argument('-j', '--dump',    action='store_true',                    help='Dumps the full VT report to file (VTDL{md5}.json), if you (re)scan many files/urls, their json data will be dumped to separetad files')
  
  domain_opt = opt.add_argument_group('Domain/IP verbose mode options, by default just show resolved IPs/Passive DNS')
  domain_opt.add_argument('--alexa-domain-info',                action='store_true', default=False, help='Just Domain option: Show Alexa domain info')
  domain_opt.add_argument('--wot-domain-info',                  action='store_true', default=False, help='Just Domain option:Show WOT domain info')
  domain_opt.add_argument('--trendmicro',                       action='store_true', default=False, help='Just Domain option: Show TrendMicro category info')
  domain_opt.add_argument('--websense-threatseeker',            action='store_true', default=False, help='Just Domain option: Show Websense ThreatSeeker category')
  domain_opt.add_argument('--bitdefender',                      action='store_true', default=False, help='Just Domain option: Show BitDefender category')
  domain_opt.add_argument('--webutation_domain',                action='store_true', default=False, help='Just Domain option: Show Webutation domain info')
  domain_opt.add_argument('--detected-urls',                    action='store_true', default=False, help='Just Domain option: Show latest detected URLs')
  domain_opt.add_argument('--pcaps',                            action='store_true', default=False, help='Just Domain option: Show all pcaps hashes')
  domain_opt.add_argument('--detected-downloaded-samples',      action='store_true', default=False, help='Domain/IP options: Show latest detected files that were downloaded from this ip')
  domain_opt.add_argument('--undetected-downloaded-samples',    action='store_true', default=False, help='Domain/IP options: Show latest undetected files that were downloaded from this domain/ip')
  domain_opt.add_argument('--detected-communicated',            action='store_true', default=False, help='Domain/IP Show latest detected files that communicate with this domain/ip')
  domain_opt.add_argument('--undetected_communicated',          action='store_true', default=False, help='Show latest detected files that communicate with this domain/ip')

  #if len(sys.argv) < 2:
  #  opt.print_help()
  #  sys.exit(1)
    
  options = opt.parse_args()

  vt=vtAPI()
  
  if not options.value:
      opt.print_help()
      sys.exit()
    
  if options.verbose and (options.domain or options.ip):
    options.detected_urls = options.undetected_downloaded_samples = options.wot_domain_info = options.websense_threatseeker = \
                            options.detected_communicated = options.trendmicro = options.undetected_communicated = \
                            options.alexa_domain_info = options.bitdefender = options.webutation_domain = options.pcaps = \
                            options.detected_downloaded_samples = True
  
  if options.files:
    vt.fileScan(options.value)
  
  elif options.url_scan and not options.url_report: 
    vt.url_scan_and_report(options.value, "scan", options.verbose, options.dump)
  
  elif options.url_report and options.url_scan:
      vt.url_scan_and_report(options.value, "report", options.verbose, options.dump, '1')
    
  elif options.rescan:
    vt.rescan(options.value)

  elif options.domain:
    vt.getDomain(options.value[0], options.dump, options.trendmicro, options.detected_urls, options.undetected_downloaded_samples, options.alexa_domain_info,\
                 options.wot_domain_info, options.websense_threatseeker, options.bitdefender, options.webutation_domain, options.detected_communicated,\
                 options.undetected_communicated, options.pcaps)

  elif options.ip:
    vt.getIP(options.value[0], options.dump, options.detected_urls, options.detected_downloaded_samples, options.undetected_downloaded_samples,\
             options.detected_communicated, options.undetected_communicated)
  
  elif options.search and not options.domain and not options.ip and not options.url_scan and not options.url_report:
    parse_report(vt.getReport(options.value[0]), options.value[0], options.verbose, options.dump)

  elif options.add_comment and len(options.value) == 2:
    addComment(self, options.value[0], options.value[1])
    
  else:
    opt.print_help()
    sys.exit()

if __name__ == '__main__':
    main()
