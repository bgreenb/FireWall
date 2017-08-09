##  OpenFlow Switch as a Low Impact Firewall
### Description 
* Use iptables style rules and a json based config file to make a low impact firewall on an openflow capable switch
### Installation 
1. This program uses the [Ryu](https://github.com/osrg/ryu) controller framework, so make sure that is installed first.
2.  **Required Python Packages from PyPI :**
  
* Pycryptodome 
* IPy 
* netaddr 
3.  To allow command line arguments to work for the ryu app, add 

   ```python
     imp.load_source('firewall_v3','$PathToFirewall/FireWall/apps/firewall_v3.py')
   ```
   into your /ryu/cmd/manager.py file in the part right after where the modules are loaded

### Running the Firewall
* Use the included GroupGen utility to make your group config file 
* Start the controller using:
```shell 
ryu-manager apps/firewall_v3.py --Rules YourRules.txt --Groups YourGroupConfig.conf --SigFile YourGroupSignature.sig --verbose

```
