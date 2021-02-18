### About Mininet-WiFi
Mininet-WiFi is a fork of Mininet (http://mininet.org/) which allows the using of both WiFi Stations and Access Points. 
Mininet-WiFi only add wifi features and you can work with it like you were working with Mininet.   

## Installation  
**We highly recommend using Ubuntu version 18.04**  
step 1: $ sudo apt-get install git  
step 2: $ git clone https://github.com/intrig-unicamp/mininet-wifi  
step 3: $ cd mininet-wifi  
step 4: $ sudo util/install.sh -Wlnfv  
**Steps to install of modification eHDDP for mininet-wifi**  
step 5: Copy the content in mn-wifi-uah folder into mininet-wifi/mn-wifi/.  
step 6: Reinstall mininet-wifi using $ sudo python setup install  

#### install.sh options:   
-W: wireless dependencies   
-n: mininet-wifi dependencies    
-f: OpenFlow   
-v: OpenvSwitch   
-l: wmediumd   
_optional_:  
-P: P4 dependencies    
-6: wpan tools  


