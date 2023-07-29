# fit
Firewall Inspection Tester

Author: Alex Harvey, @meshmeld, 
Fixes and enhancements by Brent Wesley, @ratava, 07/2023

fit.py is design to simulate traffic for testing modern firwall blocking techniques.  
## WARNING If you use this script in a production monirtored environment it will trigger a large amount of alerts. Inclding Antivirus. No virus code is executed by this script but attempts will be made to acces sites and IP's with know bad code and ssl certificates. This includes lists from the follwing sources.

IP Reputation Testing - firehol.org Webclient ip reputation list
AV Testing - VX Vault
AV Testing - eicar.org
WF blocking - Chrome Malicious Website list  
Malware URL's - urlhaus.abuse.ch Last 30 days list
APP Ctrl - Application control triggers  
Good Web Traffic - Good web traffic (great for testing request througput, tests conducted in browser)

N.B. Please contact me if you wish to see any further data sources added.
# Installing

FIT runs under python3, the recommend installation menthod is to use pyvenv. 

```
pyvenv env
source env/bin/activate
pip install -r requirements.txt
```

FIT also requires that you have FireFox or Chrome installed. Use --chrome to use Chrome  
### Selenium works better with Firefox. Chrome will display console erros.  
# Screenshot

![screenshot](https://github.com/ratava/fit/blob/main/screenshot.png)

# Quick mode  
By default FIT will not use a quick test mode. The following applies:  
  iprep: 100 enties  
  vxvault: 100 entries  
  maulwareurls: 100 entries  
  appctrl: full  
  wf: 100 entries  
  webtraffic: 20 entries  
Use command line option --full to runn full lists

# Logging
FIT how ahs full logging. fit.out will recreated each session and contain additional information including individual result from each url/ip tested. Use this file to cross reference you Firewall logs.  

# Using FIT
## Command Line
python fit.py command [--option] 

all - run all tests  
iprep - ip repulation  
vxvault - vx vault malware url list  
eicar - eicar.org mock virus download test  
malwareurls - urlhouse malware url test  
appctrl - application control testing  
wf -Webfilter Categories  
webtraffic - Good Web Traffic testing  

## Options
--full
  Run Test in full list mode. Default quick mode

--srcip {ip} / -s {ip}
  Let's you set the source IP used by fit. You can use multiple -s/--srcip to set multiple source IPs. This increases the number of clients seen. You will need to setup your network card to use a unique MAC per IP, or the reported results will not be as desiered.

--chrome
  use Chrome instead of the default Firefox browser for Web Traffic tests.

--repeat  
  Option on the ```all``` command. Will run the traffic in a loop, useful in a lab style enviroment. 
