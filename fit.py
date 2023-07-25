#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import requests
import requests_toolbelt
import telnetlib
import socket
import random
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver
import selenium
import platform

# disable warnings in requests for cert bypass
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__version__ = 0.21

# some console colours
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

if platform.system() == "Windows":
	W = ''  # white (normal)
	R = ''  # red
	G = ''  # green
	O = ''  # orange
	B = ''  # blue
	P = ''  # purple
	C = ''  # cyan
	GR = ''  # gray



def banner():
    '''Print stylized banner'''
    print(r"""
                          ,----,
                        ,/   .`|
    ,---,.   ,---,    ,`   .'  :
  ,'  .' |,`--.' |  ;    ;     /
,---.'   ||   :  :.'___,/    ,'
|   |   .':   |  '|    :     |
:   :  :  |   :  |;    |.';  ;
:   |  |-,'   '  ;`----'  |  |
|   :  ;/||   |  |    '   :  ;
|   |   .''   :  ;    |   |  '
'   :  '  |   |  '    '   :  |
|   |  |  '   :  |    ;   |.'
|   :  \  ;   |.'     '---'
|   | ,'  '---'
`----'
Firewall Inspection Tester
Author: Alex Harvey, @meshmeld, 
Updated IP Lists and various fixes/enhancements by Brent Wesley, @ratava, 07/2023""")
    print("Version: %0.2f\n" % __version__)


def checkconnection():
    ''' check network connection '''
    try:
        r = requests.get("https://www.google.ca", verify=False)
    except:
        return False
    else:
        return True


def checkips(srcip):
    for ipaddr in srcip:
        try:
            socket.inet_aton(ipaddr)
            print(G + "[+] " + W + "Source IP Address " + ipaddr)
        except socket.error:
            print(R + "[-] " + W + "IP Address " + ipaddr + " is not valid")
            exit(-1)

def setsrcip(srcip):
    ''' Set a random source ip from a list '''
    ip = random.choice(srcip)
    s = requests.Session()
    s.mount("http://", requests_toolbelt.adapters.source.SourceAddressAdapter(ip))
    s.mount("https://", requests_toolbelt.adapters.source.SourceAddressAdapter(ip))
    return s


@click.group(chain=True)
def cli():
    banner()
    if checkconnection():
        print(G + "[+] " + W + "Network connection is okay")
    else:
        print(R + "[!] " + W + "Network connection failed")
        print(R + "[!] " + W + "Please verify the network connection")
        exit(-1)


@cli.command()
@click.option('--repeat/--no-repeat', default=False)
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.")
@click.option('--chrome', is_flag=True, help="Run Website tests in Chrome instead of FireFox.")
def all(repeat, srcip, full, chrome):
    '''Run all test one after the other'''
    checkips(srcip)
    if repeat:
        print(G + "[+] " + W + "Repeat, repeat, repeat...")

    if not full:
      print(G + "[+] " + W + "Running in quick mode. Use --full to override")

    if not chrome:
      print(G + "[+] " + W + "FireFox will be used for Web Traffic testing. Use --chrome to use Chrome")

    while True:
        _iprep(srcip, full)
        _vxvault(srcip, full)
        _malwareurls(srcip, full)
        _appctrl(full)
        _wf(full)
        #_webtraffic(full, chrome)
        if repeat == False:
            exit()


@cli.command()
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.")
def iprep(srcip, full):
    '''IP Reputation test using zeustracker uiplist'''
    checkips(srcip)
    _iprep(srcip, full)


def _iprep(srcip, full):
    '''IP Reputation test using firehol.org webclient'''
    # https://iplists.firehol.org/files/firehol_webclient.netset
    print(G + "[+] " + W + "IP Reputation Test")
    print(G + "[+] " + W + "Fetching bad ip list...", end=" ")
    r = requests.get("https://iplists.firehol.org/files/firehol_webclient.netset", verify=False)
    print("Done")

    # clean up list
    data2 = []
    data = r.text.split("\n")
    for line in data:
        if len(line) > 1:
            if line[0] != "#":
              if line.count('/') == 0:
                data2.append(line)
    data = data2[:100]

    if full:
      print(G + "[+] " + W + "We are full mode.")
      data = data2  
    
    count = str(len(data))
    print(G + "[+] " + W + "Added " + count + " Reputation IP's")

    with click.progressbar(data, label="Checking IP's", length=len(data)) as ips:
        for ip in ips:
            try:
                tn = telnetlib.Telnet(ip, 443, 1)
            except (socket.timeout, socket.error, ConnectionRefusedError):
                pass


@cli.command()
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.")
def vxvault(srcip, full):
    '''Malware samples download from vxvault'''
    checkips(srcip)
    _vxvault(srcip, full)


def _vxvault(srcip, full):
    '''Malware samples download from vxvault'''
    # http://vxvault.net/URL_List.php
    print(G + "[+] " + W + "VX Vault Malware Downloads")
    print(G + "[+] " + W + "Fetching VXVault list...", end=" ")
    r = requests.get("http://vxvault.net/URL_List.php", timeout=10)
    print("Done")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    # clean up list
    data2 = []
    data = r.text.split("\r\n")
    for line in data:
        if len(line) > 1:
            if line[0] == "h":
                data2.append(line)
    
    data = data2[:100]

    if full:
      print(G + "[+] " + W + "We are full mode.")
      data = data2  
    
    count = str(len(data))
    print(G + "[+] " + W + "Added " + count + " Online Malware URLs")


    with click.progressbar(data, label="Testing Malware Url's", length=len(data)) as urls:
        for url in urls:
            try:
                if len(srcip) > 0:
                    r = setsrcip(srcip).get(url, timeout=1)
                else:
                    r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                pass


@cli.command()
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.")
def malwareurls(srcip, full):
    '''  Malware URl/Domain test '''
    checkips(srcip)
    _malwareurls(srcip, full)


def _malwareurls(srcip, full):
    '''  Malware URl/Domain test '''
    # https://urlhaus.abuse.ch/downloads/csv_recent/
    # Only top 100 online classified urls are processed unless --full is specified
    print(G + "[+] " + W + "Malware URL Downloads")
    print(G + "[+] " + W + "Fetching Malware URL list...", end=" ")
    r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", verify=False)
    print("Done")

    # clean up list
    data2 = []
    data = r.text.split("\n")
    for line in data:
        if len(line) > 1:
            if line[0] != "#":
              line1 = line.replace("\"","")
              split_line = line1.split(",")
              if split_line[3] == "online": 
                data2.append(split_line[2])
    data = data2[:100]

    if full:
      print(G + "[+] " + W + "We are full mode.")
      data = data2  
    
    count = str(len(data))
    print(G + "[+] " + W + "Added " + count + " Online Malware URLs")

    if len(srcip) > 0:
        print(G + "[+] " + W + "Multi source IP mode enabled")

    with click.progressbar(data, label="Testing Malware Url's", length=len(data)) as urls:
         for url in urls:
             try:
                 if len(srcip) > 0:
                     r = setsrcip(srcip).get(url, timeout=1)
                 else:
                     r = requests.get(url, timeout=1)
             except requests.exceptions.RequestException:
                 pass

@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
def appctrl(full):
    ''' Trigger application control '''
    _appctrl(full)


def _appctrl(full):
    ''' Trigger application control '''
    print(G + "[+] " + W + "Application Congtrol")
    print(G + "[+] " + W + "Fetching AppCtrl list...", end=" ")
    f = open("appctrl.csv", 'r')
    lines = f.read()
    print("Done")

    data2 = lines.split("\n")
    data = data2[:20]
    if full:
      print(G + "[+] " + W + "We are full mode.")
      data = data2  
    
    count = str(len(data))
    print(G + "[+] " + W + "Added " + count + " Testing URL's")

    with click.progressbar(data, label="Triggering Categories", length=len(data)) as urls:
        for url in urls:
            try:
                r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                pass


@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
def wf(full):
    '''  URL categorisation trigger '''
    _wf(full)


def _wf(full):
    '''  URL categorisation trigger '''
    # http://www.malwaredomainlist.com/mdlcsv.php
    print(G + "[+] " + W + "WF categorisation trigger")
    print(G + "[+] " + W + "Fetching URL list...", end=" ")
    # r = requests.get("http://vxvault.net/URL_List.php", timeout=1)
    f = open("wf.csv", 'r')
    lines = f.read()
    print("Done")

    data2 = lines.split("\n")
    data = data2[:100]
    if full:
      print(G + "[+] " + W + "We are full mode.")
      data = data2  
    
    count = str(len(data))
    print(G + "[+] " + W + "Added " + count + " Testing URL's")

    with click.progressbar(data, label="Triggering URL Categories.", length=len(data)) as urls:
        for url in urls:
            try:
                r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                pass


@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
@click.option('--chrome', is_flag=True, help="Run Website tests in Chrome instead of FireFox.")
def webtraffic(full, chrome):
    ''' Generate good web traffic '''
    _webtraffic(full, chrome)


def _webtraffic(full, chrome):
    if chrome: 
      driver = webdriver.Chrome()
    else:
      driver = webdriver.Firefox()
      print(G + "[+] " + W + "FireFox will be used for Web Traffic testing. Use --chrome to use Chrome")
    driver.set_window_size(1920, 1080)
    driver.set_page_load_timeout(10)

    print(G + "[+] " + W + "Web traffic trigger")
    print(G + "[+] " + W + "Fetching traffic list...", end=" ")
    f = open("goodurl.csv", 'r')
    lines = f.read()
    print("Done")


    data2 = lines.split("\n")
    data = data2[:20]
    if full:
      print(G + "[+] " + W + "We are full mode.")
      data = data2  
    
    count = str(len(data))
    print(G + "[+] " + W + "Added " + count + " Testing URL's")

    with click.progressbar(data, label="Generating Web Traffic", length=len(data)) as urls:
        for url in urls:
            try:
                driver.get("http://www.%s" % url)
            except selenium.common.exceptions.TimeoutException:
                pass

    driver.quit()


if __name__ == '__main__':
    cli()
