#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Built on (Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity)
# Updated with full VT APIv2 functions by Andriy Brukhovetskyy (DoomedRaven)
# No Licence or warranty expressed or implied, use however you wish! 
# For more information look at https://www.virustotal.com/es/documentation/public-api

import hashlib
import postfile
from pprint import pprint
from operator import methodcaller
import json, urllib, urllib2, argparse, hashlib, re, sys


def jsondump(jdata, md5):
    if jsondump == True:
        jsondumpfile = open('VTDL{md5}.json'.format(md5 = md5), 'w')
        pprint(it, jsondumpfile)
        jsondumpfile.close()
        print '\n\tJSON Written to File -- VTDL{md5}.json'.format(md5 = md5)
 
class vtAPI():
    
    def __init__(self):
        
        self.api = '<--------------PUBLIC-API-KEY-GOES-HERE----->'
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
            hash_re = hash_re[0]
        elif len(hash_re) > 25:
            print '[-] To many urls for scanning, MAX 25'
            sys.exit()
        else:
            hash_re = ', '.join(map(lambda hash_part: hash_part, hash_re))
        
        param  = {'resource':hash_re,'apikey':self.api}
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
        
        host  = 'www.virustotal.com'
        param = [('apikey',self.api)]
        url   = self.base + 'file/scan'
        file_upload = open(files, 'rb').read()
        files = [("file", files, file_upload)]
        result  = postfile.post_multipart(host, url, param, files)
        jdata  =  json.loads(result)
        
        print '\n\tResults for MD5:    ',jdata['md5']
        print '\tResults for SHA1:   ',jdata['sha1']
        print '\tResults for SHA256: ',jdata['sha256']
        
        print '\n\tStatus        ',jdata['verbose_msg']
        print '\tPermament link',jdata['permalink'],'\n'
        
    def urlScan(self, urls):
        
        if len(urls) == 1:
            url_upload = urls[0]
        elif len(urls) > 4:
            print '[-] To many urls for scanning, MAX 4'
            sys.exit()
        else:
            url_upload = '\n'.join(map(lambda url: url, urls))
            
        param = {'resource':url_upload,'apikey':self.api}
        url = self.base + 'url/scan'
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata  =  json.loads(result.read())
        
        if isinstance(jdata, list):
          for jdata_part in jdata:
            print '\tStatus',jdata_part['verbose_msg'], '\t', jdata_part['url']
            print '\tPermanent link:', jdata_part['permlink']
            
            if jsondump == True:
                md5 = hashlib.md5(jdata_part['url']).hexdigest()
                jsondump(jdata, md5)
    
        else:
          print '\tStatus',jdata['verbose_msg'], jdata['url']
          print '\tPermanent link:',jdata['permlink']
          if jsondump == True:
            md5 = hashlib.md5(jdata["url"]).hexdigest()
            jsondump(jdata, md5)
        
    def getIP(self, ip):
        param  = {'ip':ip,'apikey':self.api}
        url    = self.base + 'ip-address/report'
        data   = urllib.urlencode(param)
        result = urllib.urlopen('{url}?{data}'.format(url = url, data = data))
        jdata  =  json.loads(result.read())
        
        if jsondump == True:
            md5 = hashlib.md5(ip).hexdigest()
            jsondump(jdata, md5)
        
        print '\nStatus:         ', jdata['verbose_msg'],'\n'
    
        for data in  sorted(jdata['resolutions'], key=methodcaller('get', 'last_resolved'), reverse=True):
          print "Last resolved","    --    " if data["last_resolved"] == None else data["last_resolved"].split(" ")[0], "Hostname", data["hostname"]
        
    
    def getDomain(self, domain, trendmicro, detected_urls, undetected_downloaded_samples, alexa_domain_info, wot_domain_info, websense_threatseeker,\
                  bitdefender, webutation_domain, detected_communicated, undetected_communicating_samples, pcaps):
        
        """
        Get domain last scan, detected urls and resolved IPs
        """
        param  = {'domain':domain,'apikey':self.api}
        url    = self.base + "domain/report"
        data   = urllib.urlencode(param)
        result = urllib.urlopen("{url}?{data}".format(url = url, data = data))
        jdata  =  json.loads(result.read())
        
        if jsondump == True:
            md5 = hashlib.md5(domain).hexdigest()
            jsondump(jdata, md5)
            
        print '\nStatus:         ', jdata['verbose_msg'],'\n'
        
        if trendmicro:
            print '[+] TrendMicro category'
            print '\t',jdata['TrendMicro category'],'\n'
        
        if websense_threatseeker:
            print '[+] Websense ThreatSeeker category'
            print '\t', jdata['Websense ThreatSeeker category'],'\n'
        
        if bitdefender:
            print '[+] BitDefender category'
            print '\t', jdata["BitDefender category"],'\n'
        
        if alexa_domain_info:
          print '[+] Alexa domain info'
          print '\t', jdata['Alexa domain info'],'\n'
        
        if wot_domain_info:
          print '[+] WOT domain info'
          for jdata_part in jdata['WOT domain info']:
            print '\t',jdata_part,'\t' if len(jdata_part) < 7 else '','\t' if len(jdata_part) < 14 else '','\t',jdata['WOT domain info'][jdata_part]
          
          print '\n'
        
        if webutation_domain:
          print "[+] Webutation"
          for jdata_part in jdata['Webutation domain info']:
            print '\t', jdata_part,'\t' if len(jdata_part) < 7 else '','\t' if len(jdata_part) < 14 else '','\t',jdata['Webutation domain info'][jdata_part]
          
          print '\n'
        
        if detected_urls:
          print '[+] Latest detected URLs'
          for row in sorted(jdata['detected_urls'], key=methodcaller('get', 'scan_date'), reverse=True):
            print '\t','{positives}/{total}'.format(positives = row["positives"],total = row["total"]), '\t' ,'    --    ' if row['scan_date'] == None\
                                                                                           else row['scan_date'].split(' ')[0],'\t', row["url"]
          print '\n'
          
        if undetected_downloaded_samples:
          print '[+] Latest undetected files that were downloaded from this domain'
          for json_part in sorted(jdata["undetected_downloaded_samples"], key=methodcaller('get', 'date'), reverse=True):
            print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                      '\t','Sha256 :', json_part['sha256']
          print '\n'
        
        if detected_communicated:
          print "[+] Latest detected files that communicate with this domain"
          for json_part in sorted(jdata['detected_communicating_samples'] , key=methodcaller('get', 'scan_date'), reverse=True):
            print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                      '\t','Sha256 :', json_part['sha256']
          print "\n"
            
        if undetected_communicating_samples:
          print '[+] Latest undetected files that communicate with this domain"'              
          for json_part in sorted(jdata['undetected_communicating_samples'] , key=methodcaller('get', 'scan_date'), reverse=True):
            print '\t','{positives}/{total}'.format(positives = json_part['positives'], total = json_part['total']),'\t',json_part['date'],\
                                                                                                      '\t','Sha256 :', json_part['sha256']
          print '\n'
          
        if pcaps:
          print '[+] Pcaps'
          for jdata_part in jdata['pcaps']:
            print '\t',jdata_part
          print '\n'
         
        print '[+] Passive DNS replication'
        for row in sorted(jdata['resolutions'], key=methodcaller('get', 'last_resolved'), reverse=True):
          print "\t","    --    " if row["last_resolved"] == None else row["last_resolved"].split(" ")[0], '\t', row['ip_address']
        
    def addComment(self, hash_co, comment):
        param  = {'resourse':md5,'comment':comment,'apikey':self.api}
        url    = self.base + "comments/put"
        data   = urllib.urlencode(param)
        result = urllib2.Request(url, data)
        jdata  =  json.loads(result.read())
        
        print '\nStatus:         ', jdata['verbose_msg'],'\n'
          
def parse_search_report(it, hash_report, verbose, jsondump):
  if it['response_code'] == 0:
    print md5 + " -- Not Found in VT"
    return 0

  print "\n\tScanned on:          ",it['scan_date']
  print "\tDetected by:         ",it['positives'],'/',it['total']

  print "\n\tSophos Detection:    ",it['scans']['Sophos']['result']
  print "\tKaspersky Detection: ",it['scans']['Kaspersky']['result']
  print "\tTrendMicro Detection:",it['scans']['TrendMicro']['result']
  

  print "\n\tResults for MD5:    ",it['md5']
  print "\tResults for SHA1:   ",it['sha1']
  print "\tResults for SHA256: ",it['sha256']
  
  if jsondump == True:
    jsondump(it, hash_report)

  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result'] 
   
  print "\n\tPermanent Link:     ",it['permalink'],"\n"

def main():
  opt=argparse.ArgumentParser('value',description='Scan/Search/ReScan')

  opt.add_argument('value', nargs='*', help='Enter the MD5, Path to File or Url')
  opt.add_argument('-f', '--file-scan',   action='store_true', dest='files',   help='File scan, file upload by default work over HTTPS')
  opt.add_argument('-u', '--url-scan',    action='store_true', dest='urls',    help='Url scan, support space separated list, Max 4 urls')
  opt.add_argument('-r', '--rescan',      action='store_true',                 help='Force Rescan with Current A/V Definitions by MD5/SHA1/SHA256, support space separated list, MAX 25 hashes')
  opt.add_argument('-d', '--domain-info', action='store_true', dest='domain',  help='Retrieving domain reports')
  opt.add_argument('-i', '--ip-info',     action='store_true', dest='ip',      help='Retrieving IP address reports')
  opt.add_argument('-s', '--search',      action='store_true',                 help='Search VirusTotal by MD5/SHA1/SHA256')
  opt.add_argument('-c', '--add-comment', action='store_true',                 help='Add comment to analysis report, first hash and then your comment, supported hashes MD5/SHA1/SHA256')
  opt.add_argument('-v', '--verbose',     action='store_true', dest='verbose', help='Turn on verbosity of VT reports')
  opt.add_argument('-j', '--jsondump',    action='store_true',                 help='Dumps the full VT report to file (VTDL{md5}.json), if you (re)scan many files/urls, their json data will be dumped to separetad files')
  
  domain_opt = opt.add_argument_group('Domain verbose mode options, by default just show resolved IPs/Passive DNS')
  domain_opt.add_argument('--alexa-domain-info',                action='store_true', default=False, help='Show Alexa domain info')
  domain_opt.add_argument('--wot-domain-info',                  action='store_true', default=False, help='Show WOT domain info')
  domain_opt.add_argument('--trendmicro',                       action='store_true', default=False, help='Show TrendMicro category info')
  domain_opt.add_argument('--websense-threatseeker',            action='store_true', default=False, help='Show Websense ThreatSeeker category')
  domain_opt.add_argument('--bitdefender',                      action='store_true', default=False, help='Show BitDefender category')
  domain_opt.add_argument('--webutation_domain',                action='store_true', default=False, help='Show Webutation domain info')
  domain_opt.add_argument('--detected-urls',                    action='store_true', default=False, help='Show latest detected URLs')
  domain_opt.add_argument('--pcaps',                            action='store_true', default=False, help='Show all pcaps hashes')
  domain_opt.add_argument('--undetected-downloaded-samples',    action='store_true', default=False, help='Show latest undetected files that were downloaded from this domain')
  domain_opt.add_argument('--detected-communicated',            action='store_true', default=False, help='Show latest detected files that communicate with this domain')
  domain_opt.add_argument('--undetected-communicating-samples', action='store_true', default=False, help='Show latest detected files that communicate with this domain')
  
  
  if len(sys.argv) < 2:
    opt.print_help()
    sys.exit(1)
    
  options = opt.parse_args()
      
  vt=vtAPI()
  
  if options.files: 
    vt.fileScan(options.value[0])
  
  if options.urls: 
    vt.urlScan(oprions.value)
    
  if options.rescan:
    vt.rescan(options.value)

  if options.domain:
    if options.verbose:
        options.detected_urls = options.undetected_downloaded_samples = options.wot_domain_info = options.websense_threatseeker = \
                                options.detected_communicated = options.trendmicro = options.undetected_communicating_samples = \
                                options.alexa_domain_info = options.bitdefender = options.webutation_domain = options.pcaps = True
        
    vt.getDomain(options.value[0], options.trendmicro, options.detected_urls, options.undetected_downloaded_samples, options.alexa_domain_info,\
                 options.wot_domain_info, options.websense_threatseeker, options.bitdefender, options.webutation_domain, options.detected_communicated,\
                 options.undetected_communicating_samples, options.pcaps)

  if options.ip:
    vt.getIP(options.value[0])
  
  if options.search or options.jsondump or options.verbose and not options.domain:
    parse_search_report(vt.getReport(options.value[0]), options.value[0],options.verbose, options.jsondump)

  if options.add_comment and len(options.value) == 2:
    addComment(self, options.value[0], options.value[1])
  else:
    opt.print_help()

if __name__ == '__main__':
    main()


#Todo
#add list max 25 file rescans
