##  OpenFlow Switch as a Low Impact Firewall
### Description 
* Use iptables style rules and a json based config file to make a low impact firewall on an openflow capable switch

* Ability to create groups of related ip addresses, subnets, hostnames, ... etc, for easier rule creation. 

* Extended capabilities include python-style regex support and expandability via plugins for letting packets through

### Compatibility 

* Written only for Python 2.7 for now

* Tested only on a CentOS 6.8 based system, but should work on most linux distributions
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
   into your /ryu/cmd/manager.py file in the part right after where the modules are loaded. 
   In addition the imp module should be imported in manager.py as well.

### Running the Firewall
* Use the included GroupGen utility to make your group config file 
* Start the controller using:
```shell 
ryu-manager firewall_v3.py --Rules YourRules.txt --Groups YourGroupConfig.conf --SigFile YourGroupSignature.sig --Key YourPublicKey.pub --verbose

```
* The public key provided to the --Key argument will be used to verify the group config file against the generated signature passed in by --SigFile

### Writing Plugins 

* In the plugins directory, you can write a small python script that can extend the number of ways to verify that incoming ip addresses to the controller are part of a defined group. Included in that directory is a template for a plugin that includes a verify method which the ryu app will call when the included methods of group checking fail.
 
* For now the controller will take anything in the plugins directory with a .py extension and treat it as a plugin.

