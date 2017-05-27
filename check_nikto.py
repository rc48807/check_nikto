#! /usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Script to scan websites looking for web vulnerabilities

Creation date: 05/03/2017
Date last updated: 19/03/2017

Nagios check_nikto plugin
* 
* License: GPL
* Copyright (c) 2017 DI-FCUL
* 
* Description:
* 
* This file contains the check_nikto plugin
* 
* Use the nrpe program to check update information for wordpress in remote host.
* 
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
import socket
from datetime import datetime 
from collections import Counter
import time
import codecs
import sys
import urllib.request
import re
import urllib
from optparse import OptionParser
import os

__author__ = "\nAuthor: Raimundo Henrique da Silva Chipongue\nE-mail: fc48807@alunos.fc.ul.pt, chipongue1@gmail.com\nInstitution: Faculty of Science of the University of Lisbon\n"
__version__= "1.0.0"

# define exit codes
ExitOK = 0
ExitWarning = 1
ExitCritical = 2
ExitUnknown = 3

def check_connectivity():
    '''
    Check if the internet conection is up
    '''
    try:
        urllib.request.urlopen('https://google.com', timeout=1)
        return True
    except urllib.request.URLError:
        return False
  
def version(opts):   
    if check_connectivity():
        report = ("%s.html"%opts.report) 
        time_to_check = 60 * 60 * 24 * opts.time
        domain = opts.host
        domain = domain.replace("https://", "")
        domain = domain.replace("http://", "")
        domain = domain.replace("www.", "")
        if domain:
            try:
                socket.gethostbyname_ex(domain)
                num = True
            except:
                num = False           
                if not num:
                    try:
                        domain = ("www.%s"%domain)
                        socket.gethostbyname_ex(domain)
                    except:
                        print('Unable to resolve "%s"'%domain)

        if os.path.exists("%s%s"%(opts.path,report)):
            file_ts = float(os.path.getatime("%s%s"%(opts.path,report)))
            current_ts = float(time.time())
            dif = current_ts - file_ts
            if dif > time_to_check:
                if opts.tuning:
                    tuning = opts.tuning.replace(",", "") 
                    os.popen("rm %s%s"%(opts.path,report))
                    os.popen('nikto -Tuning %s -h %s -output %s%s -Format html -port %s'%(tuning, domain, opts.path, report, opts.port)).read()
                else:
                    os.popen("rm %s%s"%(opts.path,opts.report))
                    os.popen('nikto -h %s -output %s%s -Format html -port %s'%(domain, opts.path, report, opts.port)).read()
        else:
            if opts.tuning:
                tuning = opts.tuning.replace(",", "")                
                os.popen('nikto -Tuning %s -h %s -output %s%s -Format html -port %s'%(tuning, domain, opts.path, report, opts.port)).read()
            else:
                os.popen('nikto -h %s -output %s%s -Format html -port %s'%(domain, opts.path, report, opts.port)).read()
        try:
            size = os.path.getsize("%s%s"%(opts.path,report))
        except:
            print("Unable to read the file, verify that it exists and the nagios user has permissions of writing and reading in this path.")
            sys.exit(ExitUnknown)
        if size > 0:
            try:
                file = codecs.open("%s%s"%(opts.path,report))
            except:
                print("report error")
                sys.exit(ExitUnknown)
            osvdb = []
            end_scan = False
            for line in file:
                x = re.search('>OSVDB-[0-9]?\d', line)
                scan_summary = re.search('Scan Summary', line)
                if scan_summary:
                    end_scan = True
                if x:
                    osvdb.extend(re.findall(r'>(.*?)<', str(line)))
            if end_scan:
                num = (len(osvdb))
                if num != len(set(osvdb)):
                    class MyCounter(Counter):
                        def __str__(self):
                            return ("\n".join('{} {}'.format(k, v) for k, v in self.items()))
                    
                    vuln = MyCounter(Counter(osvdb))
                    vuln = str(vuln).replace("\n", ", ")

                else:
                    vuln = (', '.join(osvdb))
                
                if num:
                    print("Were found the folowing %s vulnerabilities %s, in %s, please open the file %s%s for more details."%(num, vuln, domain, opts.path, report))
                    sys.exit(ExitCritical)
                else:
                    print("The Nikto web scan didn't find any vulnerability in %s"%domain)
                    sys.exit(ExitOK)
            else:
                print("Scan in progress")
                sys.exit(ExitUnknown)
        else:
            print("Can't read file")
            sys.exit(ExitUnknown)
    else:
        print('Error, check you internet connection')
        sys.exit(ExitUnknown)

def main():
    parser = OptionParser("usage: %prog [options] arg1 arg2 arg3 arg4. \nEx.: %prog -H ciencias.ulisboa.pt -p 80 -r ciencias -t 2 -T 9" )
    parser.add_option("-H","--host", dest="host", help="Use this options to specify the target host")
    parser.add_option("-P", "--path", dest="path", default="/tmp/", type="string",
                      help="Use this option to specify the path to save the nikto report." +
                      " By default this is /tmp folder, however this doesn't secure, any malicious user can change the" +
                      " your content, and generating false positives or false negatives." +
                      " If the folder is different from /tmp, you must assign read and write permissions to nagios.")
    parser.add_option("-p", "--port", dest="port", default="443",
                      help="Use this option to specify the port or ports", type="string")
    parser.add_option("-r", "--report", dest="report", default="report",
                      help="Use this option to specify the report name", type="string")
    parser.add_option("-t", "--time", dest="time", default=1,
                      help="Use this option to specify the life time for report file, life time is in day.", type=float)
    parser.add_option("-T", "--tuning", dest="tuning", default=False,
                      help="Use this option to select the tuning mode, and specify the options you need to work."+
                      "Using Tuning mode, this implies the selection of tests, running in short time,"+
                      "that run in normal mode, takes a several minutes."+
                      " | 0 - File Upload"+
                      " | 1 - Interesting File // we will get in logs"+
                      " | 2 - Misconfiguration // Defoult File"+
                      " | 3 - Information Disclousure"+
                      " | 4 - Injection (XSS/Script/HTML)"+
                      " | 5 - Remote File Retrievel - Inside Web Root"+
                      " | 6 - Denial of Service // Scan for DDOS"+
                      " | 7 - Remote File Retrieval - Server Wide"+
                      " | 8 - Command Execution // Remote Shell"+
                      " | 9 - SQL Injection // Scan for mysql vulnerabilities"+
                      " | a - Authentication Bypass"+
                      " | b - Software Identification"+
                      " | c - Remote Source Inclusion"+
                      " | x - Reverse Tuning Options",
                      type="string")
    parser.add_option("-V","--version", action="store_true", dest="version", help="This option show the current version number of the program and exit")
    parser.add_option("-A","--author", action="store_true", dest="author", help="This option show author information and exit")
    (opts, args) = parser.parse_args()
    if not os.path.exists(opts.path):
        parser.error("Please, this program requires to specify a valid and private folder to store temp file")
    if opts.author:
        print(__author__)
        sys.exit()
    if opts.version:
        print("check_nikto.py %s"%__version__)
        sys.exit()

    if not opts.host:
        parser.error("This script requires to specify host arguments.") 
        sys.exit(ExitUnknown)

    version(opts)

if __name__ == '__main__':
    main()

