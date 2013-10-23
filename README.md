VirusTotal public APIv2 Full support
===================

This script was made public into the official VT API documentation page.
https://www.virustotal.com/en/documentation/public-api/

For working, you need to set your api key at line 55<br />

Orginal Script Author: Adam Meyers<br />
Rewirtten & Modified: Chris Clark<br />
And finally has been added full API support by Andriy Brukhovetskyy (doomedraven)<br />

License: Do whatever you want with it :)<br />

Some examples:<br />

<pre><code>python vt.py -d google.com

Status:          Domain found in dataset 

[+] Passive DNS replication
	2013-10-19 	74.125.142.100
	2013-10-19 	74.125.142.102
	2013-10-19 	74.125.142.139
	2013-10-19 	74.125.193.100
	2013-10-19 	74.125.193.101
	....


python vt.py -us -ur cuatvientos.org   
Searching for url(s) report: 
	cuatvientos.org

	Scanned on:           2013-10-23 18:11:02
	Detected by:          0 / 47

	Status      : Scan finished, scan information embedded in this object
	Scanned url : http://cuatvientos.org/

	Permanent Link:      https://www.virustotal.com/url/9be15bbec0dacb3ec93c462998e0ea8017efd80353a38882a94e0d5dc906e3dc/analysis/1382551862/ 	
	
	
python vt.py -s 0a1ab00a6f0f7f886fa4ff48fc70a953

	Scanned on:           2013-10-20 14:13:11
	Detected by:          15 / 48

	Sophos Detection:     Troj/PDFEx-GD
	Kaspersky Detection:  HEUR:Exploit.Script.Generic
	TrendMicro Detection: HEUR_PDFJS.STREM

	Results for MD5:     0a1ab00a6f0f7f886fa4ff48fc70a953
	Results for SHA1:    0e734df1fbde65db130e4cf23577bdf8fde73ca8
	Results for SHA256:  be9c0025b99f0f8c55f448ba619ba303fc65eba862cac65a00ea83d480e5efec

	Permanent Link:      https://www.virustotal.com/file/be9c0025b99f0f8c55f448ba619ba303fc65eba862cac65a00ea83d480e5efec/analysis/1382278391/ 
	
	
usage: value [-h] [-f] [-us] [-ur] [-r] [-d] [-i] [-s] [-c] [-v] [-j]
             [--alexa-domain-info] [--wot-domain-info] [--trendmicro]
             [--websense-threatseeker] [--bitdefender] [--webutation_domain]
             [--detected-urls] [--pcaps] [--detected-downloaded-samples]
             [--undetected-downloaded-samples] [--detected-communicated]
             [--undetected_communicated]
             [value [value ...]]

Scan/Search/ReScan

positional arguments:
  value                 Enter the Hash, Path to File or Url

optional arguments:
  -h, --help            show this help message and exit
  -f, --file-scan       File(s) scan, support linux name wildcard, example:
                        /home/user/*malware*, sleeping 5 seconds, between
                        uploads, by default work over HTTPS
  -us, --url-scan       Url scan, support space separated list, Max 4 urls
  -ur, --url-report     Url(s) report, support space separated list, Max 4
                        urls, you can use --url-report --url-scan options for
                        analysing url(s) if they are not in VT data base
  -r, --rescan          Force Rescan with Current A/V Definitions by
                        MD5/SHA1/SHA256, support space separated list, MAX 25
                        hashes
  -d, --domain-info     Retrieving domain reports
  -i, --ip-info         Retrieving IP address reports
  -s, --search          Search VirusTotal by MD5/SHA1/SHA256
  -c, --add-comment     Add comment to analysis report, first hash and then
                        your comment, supported hashes MD5/SHA1/SHA256
  -v, --verbose         Turn on verbosity of VT reports
  -j, --dump            Dumps the full VT report to file (VTDL{md5}.json), if
                        you (re)scan many files/urls, their json data will be
                        dumped to separetad files

Domain/IP verbose mode options, by default just show resolved IPs/Passive DNS:
  --alexa-domain-info   Just Domain option: Show Alexa domain info
  --wot-domain-info     Just Domain option:Show WOT domain info
  --trendmicro          Just Domain option: Show TrendMicro category info
  --websense-threatseeker
                        Just Domain option: Show Websense ThreatSeeker
                        category
  --bitdefender         Just Domain option: Show BitDefender category
  --webutation_domain   Just Domain option: Show Webutation domain info
  --detected-urls       Just Domain option: Show latest detected URLs
  --pcaps               Just Domain option: Show all pcaps hashes
  --detected-downloaded-samples
                        Domain/IP options: Show latest detected files that
                        were downloaded from this ip
  --undetected-downloaded-samples
                        Domain/IP options: Show latest undetected files that
                        were downloaded from this domain/ip
  --detected-communicated
                        Domain/IP Show latest detected files that communicate
                        with this domain/ip
  --undetected_communicated
                        Show latest detected files that communicate with this
                        domain/ip

Options -v/--verbose active verbose mode in search, and if you look for domain information,
this will be activate all domain verbose mode options
</code></pre>
 
 Tested on Mac Os X 10.8.5/10.9 and Ubuntu 12.04.4
