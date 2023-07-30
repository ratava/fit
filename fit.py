#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import requests
import requests_toolbelt
import socket
import random
from urllib3.exceptions import InsecureRequestWarning
import selenium
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# disable warnings in requests for cert bypass
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__version__ = 0.31


# pytest function
def ftest():
    return 3


# pytest function
def test_function():
    assert ftest() == 3


def banner():
    """Print stylized banner"""
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
Original Author: Alex Harvey, @meshmeld,
Updated 2023: Brent Wesley, @ratava""")
    print("Version: %0.2f\n" % __version__)


def checkconnection():
    """ check network connection """
    try:
        requests.get("https://www.google.ca", verify=False)
    except requests.exceptions.RequestException:
        return False
    else:
        return True


def checkips(srcip):
    for ipaddr in srcip:
        try:
            socket.inet_aton(ipaddr)
            print("[+] Source IP Address " + ipaddr)
        except socket.error:
            print("[-]  IP Address " + ipaddr + " is not valid")
            exit(-1)


def setsrcip(srcip):
    """ Set a random source ip from a list """
    ip = random.choice(srcip)
    s = requests.Session()
    s.mount("http://",
            requests_toolbelt.adapters.source.SourceAddressAdapter(ip))
    s.mount("https://",
            requests_toolbelt.adapters.source.SourceAddressAdapter(ip))
    return s


def setLogging():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-12s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename="fit.log",
                        filemode='w')
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("charset_normalizer").setLevel(logging.WARNING)


malwareurlsLogger = logging.getLogger('fit.malwareurls')
appctrlLogger = logging.getLogger('fit.appctrl')
badsslLogger = logging.getLogger('fit.badssl')
eicarLogger = logging.getLogger('fit.eicar')
iprepLogger = logging.getLogger('fit.iprep')
webtrafficLogger = logging.getLogger('fit.webtraffic')
wfLogger = logging.getLogger('fit.wf')
vxvaultLogger = logging.getLogger('fit.vxvault')


@click.group(chain=True)
@click.option('--full', is_flag=True, help="Run in full list mode.",
              show_default=True, default=False)
@click.option('--chrome', is_flag=True,
              help="Run Website tests in Chrome instead of FireFox.")
def cli(full, chrome):
    banner()
    setLogging()
    if checkconnection():
        logging.info("[+] Network connection is okay")
    else:
        logging.info("[!] Network connection failed")
        logging.info("[!] Please verify the network connection")
        exit(-1)


@cli.command()
def version():
    """Show the current version"""
    return


@cli.command()
@click.option('--repeat/--no-repeat', default=False)
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.",
              show_default=True, default=False)
@click.option('--chrome', is_flag=True,
              help="Run Website tests in Chrome instead of FireFox.")
def all(repeat, srcip, full, chrome):
    """Run all test one after the other"""
    checkips(srcip)
    if repeat:
        logging.info("Running All test on Repeat")

    if not full:
        logging.info("[+] Running in quick mode. Use --full to override")

    if not chrome:
        logging.info("[+] FireFox will be used for Web Traffic testing")

    while True:
        _iprep(full)
        _vxvault(srcip, full)
        _malwareurls(srcip, full)
        _badssl(srcip)
        _eicar()
        _appctrl(full)
        _wf(full)
        _webtraffic(full, chrome)
        if not repeat:
            exit()


@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
def iprep(full):
    """IP Reputation test using zeustracker uiplist"""
    _iprep(full)


def _iprep(full):
    """IP Reputation test using firehol.org webclient"""
    # https://iplists.firehol.org/files/firehol_webclient.netset
    iprepLogger.info("[+] IP Reputation Test")
    iprepLogger.info("[+] Fetching bad ip list...")
    source = "https://iplists.firehol.org/files/firehol_webclient.netset"
    r = requests.get(source, verify=False)
    iprepLogger.info("[+] Done")

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
        iprepLogger.info("[+] We are full mode.")
        data = data2

    count = str(len(data))
    iprepLogger.info("[+] Added %s Reputation IP's", count)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    with click.progressbar(data, label="Checking IP's",
                           length=len(data)) as ips:
        for ip in ips:
            iprepLogger.debug("Checking %s", ip)
            if sock.connect_ex((ip, 443)) == 0:
                iprepLogger.info(f"{ip} is Blocked")
            else:
                iprepLogger.debug(f"{ip} is Open")


@cli.command()
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.")
def vxvault(srcip, full):
    """Malware samples download from vxvault"""
    checkips(srcip)
    _vxvault(srcip, full)


def _vxvault(srcip, full):
    """Malware samples download from vxvault"""
    # http://vxvault.net/URL_List.php
    vxvaultLogger.info("[+] VX Vault Malware Downloads")
    vxvaultLogger.info("[+] Fetching VXVault list...")
    r = requests.get("http://vxvault.net/URL_List.php", timeout=10)
    vxvaultLogger.info("[+] Done")

    if len(srcip) > 0:
        vxvaultLogger.info("[+] Multi source IP mode enabled")

    # clean up list
    data2 = []
    data = r.text.split("\r\n")
    for line in data:
        if len(line) > 1:
            if line[0] == "h":
                data2.append(line)

    data = data2[:100]

    if full:
        vxvaultLogger.info("[+] We are full mode.")
        data = data2

    count = str(len(data))
    vxvaultLogger.info("[+] Added %s Online Malware URLs", count)

    with click.progressbar(data, label="Testing Malware URL",
                           length=len(data)) as urls:
        for url in urls:
            try:
                if len(srcip) > 0:
                    r = setsrcip(srcip).get(url, timeout=1)
                else:
                    r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                vxvaultLogger.debug("Testing %s Blocked %s", url, r)
            else:
                vxvaultLogger.debug("Testing %s Allowed %s", url, r)


@cli.command()
@click.option('--srcip', '-s', multiple=True)
@click.option('--full', is_flag=True, help="Run in full list mode.")
def malwareurls(srcip, full):
    """  Malware URl/Domain test """
    checkips(srcip)
    _malwareurls(srcip, full)


def _malwareurls(srcip, full):
    """  Malware URl/Domain test """
    # https://urlhaus.abuse.ch/downloads/csv_recent/
    # Only top 100 online classified urls are processed unless --full is
    # specified

    malwareurlsLogger.info("[+] Malware URL Downloads")
    malwareurlsLogger.info("[+] Fetching Malware URL list...")
    r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/",
                     verify=False)
    malwareurlsLogger.info("[+] Done")

    # clean up list
    data2 = []
    data = r.text.split("\n")
    for line in data:
        if len(line) > 1:
            if line[0] != "#":
                line1 = line.replace("\"", "")
                split_line = line1.split(",")
                if split_line[3] == "online":
                    data2.append(split_line[2])
    data = data2[:100]

    if full:
        malwareurlsLogger.info("[+] We are full mode.")
        data = data2

    count = str(len(data))
    malwareurlsLogger.info("[+] Added %s Online Malware URLs", count)

    if len(srcip) > 0:
        malwareurlsLogger.info("[+] Multi source IP mode enabled")

    with click.progressbar(data, label="Testing Malware URL",
                           length=len(data)) as urls:
        for url in urls:
            try:
                if len(srcip) > 0:
                    r = setsrcip(srcip).get(url, timeout=1)
                else:
                    r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                vxvaultLogger.debug(f"Checking {url} Blocked {r}")
            else:
                vxvaultLogger.debug(f"Checking {url} Allowed {r}")


@cli.command()
@click.option('--srcip', '-s', multiple=True)
def badssl(srcip):
    """  Botnet SSL certificate check """
    checkips(srcip)
    _badssl(srcip)


def _badssl(srcip):
    """  Botnet SSL certificate check """
    # https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
    badsslLogger.info("[+] Botnet Bad SSL Certs")
    badsslLogger.info("[+] Fetching Certificate Source list...")
    r = requests.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                     verify=False)
    badsslLogger.info("[+] Done")

    # clean up list
    data2 = []
    data = r.text.split("\n")
    for line in data:
        if len(line) > 1:
            if line[0] != "#":
                line1 = line.replace("\"", "")
                split_line = line1.split(",")
                ip = split_line[1]
                port = split_line[2]
                srcurl = (f"https://{ip}:{port}")
                data2.append(srcurl)
    data = data2

    count = str(len(data))
    badsslLogger.info("[+] Added %s Certificate sources", count)

    if len(srcip) > 0:
        badsslLogger.info("[+] Multi source IP mode enabled")

    with click.progressbar(data, label="Testing SSL Cert",
                           length=len(data)) as urls:
        for url in urls:
            try:
                if len(srcip) > 0:
                    r = setsrcip(srcip).get(url, timeout=1)
                else:
                    r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                badsslLogger.debug(f"Checking {url} Blocked {r}")
            else:
                badsslLogger.debug(f"Checking {url} Allowed {r}")


@cli.command()
def eicar():
    """ Trigger application control """
    _eicar()


def _eicar():
    """  Firewall AV Eicar Test """
    # https://secure.eicar.org/eicar.com
    # Only top 100 online classified urls are processed unless --full is
    # specified
    eicarLogger.info("[+] EICAR Antivirus Test")
    eicarLogger.info("[+] Fetching EICAR mock virus...")
    url = "https://secure.eicar.org/eicar.com"
    try:
        r = requests.get(url, verify=False)
    except requests.exceptions.RequestException:
        eicarLogger.debug(f"Checking {url} Blocked {r}")
    else:
        eicarLogger.info(f"Checking {url} Allowed {r}")


@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
def appctrl(full):
    """ Trigger application control """
    _appctrl(full)


def _appctrl(full):
    """ Trigger application control """
    appctrlLogger.info("[+] Application Control")
    appctrlLogger.info("[+] Fetching AppCtrl list...")
    f = open("appctrl.csv", 'r')
    lines = f.read()
    appctrlLogger.info("[+] Done")
    f.close()

    data2 = lines.split("\n")
    data = data2[:20]
    if full:
        appctrlLogger.info("[+] We are full mode.")
        data = data2

    count = str(len(data))
    appctrlLogger.info(f"[+] Added {count} Testing URLs")

    with click.progressbar(data, label="Triggering Categories",
                           length=len(data)) as urls:
        for url in urls:
            try:
                r = requests.get(url, timeout=1)
            except requests.exceptions.RequestException:
                appctrlLogger.debug(f"Checking {url} Blocked {r}")
            else:
                appctrlLogger.debug(f"Checking {url} Allowed {r}")


@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
def wf(full):
    """  URL categorisation trigger """
    _wf(full)


def _wf(full):
    """  URL categorisation trigger """
    wfLogger.info("[+] WF categorisation trigger")
    wfLogger.info("[+] Fetching URL list...")
    f = open("wf.csv", 'r')
    lines = f.read()
    wfLogger.info("[+] Done")
    f.close()

    data2 = lines.split("\n")
    data = data2[:100]
    if full:
        wfLogger.info("[+] We are full mode.")
        data = data2

    count = str(len(data))
    wfLogger.info("[+] Added %s Testing URLs", count)

    with click.progressbar(data, label="Testing URL.",
                           length=len(data)) as urls:
        for url in urls:
            try:
                requests.get("https://www.%s" % url, timeout=2)
            except requests.exceptions.RequestException:
                wfLogger.debug(f"Checking {url} Blocked")
            else:
                wfLogger.debug(f"Checking {url} Allowed")


@cli.command()
@click.option('--full', is_flag=True, help="Run in full list mode.")
@click.option('--chrome', is_flag=True,
              help="Run Website tests in Chrome instead of FireFox.")
def webtraffic(full, chrome):
    """ Generate good web traffic """
    _webtraffic(full, chrome)


def _webtraffic(full, chrome):
    webtrafficLogger.info("[+] Web traffic Generator")
    webtrafficLogger.info("[+] Fetching traffic list...")
    if chrome:
        webtrafficLogger.info("[+] Opening Chrome")
        options = Options()
        options.page_load_strategy = 'eager'
        driver = webdriver.Chrome(options=options)
    else:
        webtrafficLogger.info("[+] Opening Firefox")
        options = webdriver.FirefoxOptions()
        options.page_load_strategy = 'eager'
        driver = webdriver.Firefox(options=options)

    driver.set_window_size(1920, 1080)
    driver.set_page_load_timeout(10)

    f = open("goodurl.csv", 'r')
    lines = f.read()
    webtrafficLogger.info("[+] Done")
    f.close()

    data2 = lines.split("\n")
    data = data2[:20]
    if full:
        webtrafficLogger.info("[+] We are full mode.")
        data = data2

    count = str(len(data))
    webtrafficLogger.info(f"[+]  Added {count} Testing URLs")

    with click.progressbar(data, label="Generating Traffic",
                           length=len(data)) as urls:
        for url in urls:
            try:
                driver.get("https://www.%s" % url)
            except selenium.common.exceptions.TimeoutException:
                webtrafficLogger.debug(f"Checking {url} Unavailable")
            except selenium.common.exceptions.WebDriverException:
                webtrafficLogger.debug(f"Checking {url} Error")
            else:
                webtrafficLogger.debug(f"Accessing {url} Opened")
    driver.quit()


if __name__ == '__main__':
    cli()
