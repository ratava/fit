# fit
firewall inspection tester

Author: Alex Harvey, @meshmeld, 
Updated IP Lists and various fixes/enhancements by Brent Wesley, @ratava, 07/2023

IP Reputation Testing - firehol.org Webclient ip reputation list
AV Testing - VX Vault/Eicar  
WF blocking - Chrome Malicious Website list  
Malware URL's - urlhaus.abuse.ch Last 30 days list
APP Ctrl - Application control triggers  
Good Web Traffic - Good web traffic   
# Installing

FIT runs under python3, the recommend installation menthod is to use pyvenv. 

```
pyvenv env
source env/bin/activate
pip install -r requirements.txt
```

FIT also requires that you have FireFox or Chrome installed. Use --chrome to use Chrome 

# Screenshot

![screenshot](https://github.com/ratava/fit/raw/master/screenshot.png)

# Using FIT

all - run all tests
iprep - ip repulation
vxvault - vx vault malware url list
malwareurls - urlhouse malware url test
appctrl - application control testing
webtraffic - Good Web Traffic testing

--full 
  Run Test in full list mode. Default quick mode
--srcip {ip} / -s {ip}  
  Let's you set the source IP used by fit. You can use multiple -s/--srcip to set multiple source IPs. This increases the number of clients seen. You will need to setup your network card to use a unique MAC per IP, or the reported results will not be as desiered.
--chrome
  use Chrome instead of the default Firefox browser for Web Traffic tests.
--repeat  
  Option on the ```all``` command. Will run the traffic in a loop, useful in a lab style enviroment. 
