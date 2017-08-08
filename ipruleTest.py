from netaddr import *
from IPy import IP
import itertools
import socket
import re
import json
import sys
import os

PLUGINPATH = "plugins"

class Match(object):
    def __init__(self, name, rule=None):
        self.name = name
        self.rule = rule

    def __getattr__(self, name):
        try:
            return super(Match, self).__getattribute__(name)
        except KeyError:
            raise AttributeError

    def __setattr__(self, key, value):
        key = key.replace("-", "_")
        super(Match, self).__setattr__(key, value)

class Rule(object):
    """ Rules are entries in chains
    """

    def __init__(self, chain=None):
        self.chain = chain
        self._matches = []
        self._target = None
        self._proto = None
        self._src = None
        self._dst = None
        self._sgroup = -1
        self._dgroup = -1
        self._isDefault = False

    def create_match(self, name):
        match = Match(name)
        self.add_match(match)
        return match

    def add_match(self, match):
        match.rule = self
        self._matches.append(match)

    def remove_match(self, match):
        self._matches.remove(match)

    def _get_target(self):
        return self._target

    def _set_target(self, target):
        self._target = target
    target = property(_get_target, _set_target)

    def _get_proto(self):
        return self._proto

    def _set_proto(self, protocol):
        self._proto = protocol
    protocol = property(_get_proto, _set_proto)

    def get_src(self):
        return self._src

    def set_src(self, src):
        self._src = src
    src = property(get_src, set_src)

    def get_dst(self):
        return self._dst

    def set_dst(self, dst):
        self._dst = dst
    dst = property(get_dst, set_dst)

    def _get_sgroup(self):
	    return self._sgroup

    def _set_sgroup(self, group):
	    self._sgroup = group
    sgroup = property(_get_sgroup, _set_sgroup)

    def _get_dgroup(self):
	    return self._dgroup

    def _set_dgroup(self, dgroup):
	    self._dgroup = dgroup
    dgroup = property(_get_dgroup, _set_dgroup)

class Chain(object):

    _cache = dict()
    def __new__(cls, table, name):
        obj = Chain._cache.get(table.name + "." + name, None)
        if not obj:
            obj = object.__new__(cls)
            obj.__init__(table, name)
            Chain._cache[table.name + "." + name] = obj
            obj._rules = []
        return obj

    def __init__(self, table, name):
        self.name = name
        self.table = table
        table.add_chain(self)
        #self._rules = []

    def append_rule(self, rule):
        self._rules.append(rule)
        rule.chain = self

    def insert_rule(self, rule, position=0):
        self._rules.insert(position, rule)
        rule.chain = self

    def replace_rule(self, rule, position=0):
        self._rules[position] = rule
        rule.chain = self

    def get_rule(self, position=0):
        return self._rules[position]

    def delete_rule(self, position=-1):
        if position < 0:
            print "wrong position"
            return
        del self._rules[position]

class Table(object):

    FILTER = "filter"
    """This is the constant for the filter table."""
    MANGLE = "mangle"
    """This is the constant for the mangle table."""
    RAW = "raw"
    """This is the constant for the raw table."""
    NAT = "nat"
    """This is the constant for the nat table."""
    ALL = ["filter", "mangle", "raw", "nat"]

    _cache = dict()

    def __new__(cls, name):
        obj = Table._cache.get(name, None)
        if not obj:
            obj = object.__new__(cls)
            obj.__init__(name)
            Table._cache[name] = obj
            obj.chains = dict()
        return obj

    def __init__(self, name):
        self.name = name
        #self.chains = dict()

    def add_chain(self, chain):
        if chain.name not in self.chains:
            self.chains[chain.name] = chain
        #else :
        #    raise ValueError("chain already exist")

    def get_chain(self, chain_name):
        return self.chains[chain_name]

    def delete_chain(self, chain):
        if chain.name not in self.chians:
            raise ValueError("nothing to delete")
        else:
            del self.chains[chain.name]

#Stores all the information for a given group in a group config file and provides an abstraction in case 
#the format of the group data changes.
class GroupData(object):
    def __init__(self,groupFile):
       file = open(groupFile)
       self.data = json.JSONDecoder().decode(file.read())
       file.close()

    def isGroup(self,inputGroup):
       try:
          self.data[inputGroup]
          return True
       except:
          return False

    def reload(self,fileName):
       file = open(fileName)
       self.data = json.JSONDecoder().decode(file.read())
       file.close()

    def isIp(self,inputIp,groupName):
       ipList = self.data[groupName]["IPv4"]
       for ip in ipList:
          if ip == inputIp:
             return True
       return False

    def isFQDN(self,inputIp,groupName):
       try:
          inputFQDN = socket.gethostbyaddr(str(inputIp))[0]
       except:
          return False

       fqdnList = self.data[groupName]["FQDN"]

       for fqdn in fqdnList:
          if fqdn == inputFQDN:
             return True
       return False

    def isSubnet(self,inputIp,groupName):
       inputIp = IPAddress(inputIp)
       subList = self.data[groupName]["Subnet"]

       for subnet in subList:
          try:
             expandSub = IPNetwork(subnet)
          except:
             continue
          for ip in expandSub:
             if ip == inputIp:
                return True
       return False


class Comparison(object):
    def __init__(self, table,groupData):
        self.table = table
        self.groupData = groupData
        self.plugins = {}
        self.loadPlugins(self.plugins)

    def loadPlugins(self,pluginList):
       sys.path.insert(0,PLUGINPATH)
       for file in os.listdir(PLUGINPATH):
          fname,ext = os.path.splitext(file)
          if ext == ".py":
              mod  = __import__(fname)
              pluginList[fname] = mod.Plugin()
       sys.path.pop(0) 
       print "Plugins",pluginList

    def portMatch(self, portnum, portRange):
        ports = [int(s) for s in portRange]
        print "INPUT PORTS",ports
        print "COMPARISION PORT",portnum 
        if len(ports) == 0 or portnum == -1:
            print "PORTS MATCHED0"
            return True
        elif len(ports) == 1:
            if portnum == ports[0]:
                print "PORTS MATCHED1"
                return True
        else:
            if portnum >= ports[0] and portnum <= ports[1]:
                print "PORTS MATCHED"
                return True
        print "PORTS NOT MATCHED"
        return False

    #Is the input a valid ip address? If so return false as it can't be a dns hostname.
    def isDNS(self,str):
      try:
        IP(str)
      except ValueError:
        return True 
      return False

    #Take in an ip and get the right hostname, use this to compare to a hostname that might be in a group list. 
    def hasHostname(self,ip):
      try:
        socket.gethostbyaddr(str(ip))
      except:
        return (False,None)
      return (True,(socket.gethostbyaddr(str(ip))[0])) 

    # ipMatch1 is used to test -s with ip subnet
    def ipMatch1(self, ip, cmpIP):
        print "IN IPMATCH1"
        if cmpIP == None or cmpIP == '0.0.0.0/0.0.0.0':
            print "Blank or None cmpIP"
            return True
        if ip == None:
            return False
        if self.isDNS(str(cmpIP)):
          cmpIP = socket.gethostbyname(str(cmpIP)) 
        if '/' in cmpIP:
            ipset = IPSet([cmpIP])
            if ip in ipset:
                return True
        else:
            if ip == cmpIP:
                print "RETURNING TRUE IPMATCH1"
                return True
        print "RETURING FALSE IPMATCH1"
        return False

    #ipMatch2 is used to test ipRange
    def ipMatch2(self, ip, ipRange):
        if len(ipRange) == 0:
            return True
        if ip == None:
            return False
        if len(ipRange) == 2:
            iprange = IPRange(ipRange[0], ipRange[1])
            if ip in iprange:
                return True
        elif ip == ipRange[0]:
            return True

        return False

    #Test if two ips are from the same group file
    def groupMatch(self,sIp,dIp,sGroup,dGroup):
       sGroupMatch = False
       dGroupMatch = False

       if (self.groupData.isGroup(sGroup) == False) or (self.groupData.isGroup(dGroup) == False):
          return False
       else:
          #Verify the source ip has a match in some group
          #self.groupData.__getattribute__('isIp')
          if (self.groupData.isIp(sIp,sGroup)):
             sGroupMatch = True
          elif (self.groupData.isFQDN(sIp,sGroup)):
             sGroupMatch = True
          elif (self.groupData.isSubnet(sIp,sGroup)):
             sGroupMatch = True
          #Assume that each plugin vas a verify method for checking if an ip is in a group and use it
          else: 
             for plugin in self.plugins.values():
                try:
                   if plugin.verify(sIp,sGroup):
                      sGroupMatch = True 
                except:
                   print "Error in plugin:",self.plugins.keys()[self.plugins.values().index(plugin)], "when matching source group"
                   continue
          #Verify the destination ip has a match in some group
          if (self.groupData.isIp(dIp,dGroup)):
             dGroupMatch = True
          elif (self.groupData.isFQDN(dIp,dGroup)):
             dGroupMatch = True
          elif (self.groupData.isSubnet(dIp,dGroup)):
             dGroupMatch = True
          #Is the destination ip and group verified by a plugin method?
          else: 
             for plugin in self.plugins.values():
                try:
                   if plugin.verify(dIp,dGroup):
                      dGroupMatch = True 
                except:
                   print "Error in plugin:",self.plugins.keys()[self.plugins.values().index(plugin)], "when matching destination group"
                   continue
          
          if sGroupMatch and dGroupMatch:
             return True
          else:
             return False

    def compare(self, proto, tsIp=None, tdIp=None, tsPort=-1, tdPort=-1):

        matched_rule = {}
        for key in self.table.chains:
            print "KEY ",key
            chain = self.table.chains[key]

            for rule in chain._rules:
                dport = []
                sport = []
                srange = []
                drange = []
                src = rule.src
                dst = rule.dst
                sgroup = rule.sgroup
                print "SGROUP: ", rule.sgroup
                dgroup = rule.dgroup
                print "DGROUP: ", rule.dgroup

                if proto != rule.protocol:
                    continue

                for match in rule._matches:
                    if 'dport' in dir(match):
                        dport = match.dport.split(':')
                    if 'sport' in dir(match):
                        sport = match.sport.split(':')
                    if 'src_range' in dir(match):
                        srange = match.src_range.split('-')
                    if 'dst_range' in dir(match):
                        drange = match.dst_range.split('-')
                    print "RULE.sGROUP ",rule.sgroup
                    print "RULE.dGROUP ",rule.dgroup

                    if rule.sgroup != -1: 
                        print "tsIp=",tsIp
                        print "tdIp=",tdIp
                        print "sgroup=",sgroup
                        print "dgroup=",dgroup
                        print "sport=",sport
                        print "dport=",dport
                        print "tsPort=",tsPort
                        print "tdPort=",tdPort
                        print "ruleSource=", src
                        print "ruleDst=", dst

                        if (self.groupMatch(tsIp,tdIp,sgroup,dgroup)) and (self.portMatch(tsPort, sport)) and (self.portMatch(tdPort, dport)): 
                            
                            matched_rule['src'] = tsIp
                            matched_rule['dst'] = tdIp
                            matched_rule['proto'] = rule.protocol
                            matched_rule['target'] = rule.target
                            return matched_rule

                    elif rule.sgroup == -1:
                       print "GOT INTO ELSE"
                       print "tsIp=",tsIp
                       print "tdIp=",tdIp
                       print "sgroup=",sgroup
                       print "dgroup=",dgroup
                       print "ruleSource=", src
                       print "ruleDst=", dst
                            
                       if (self.ipMatch1(tsIp, src)) and (self.ipMatch1(tdIp, dst)) \
                       and (self.portMatch(tsPort, sport)) and (self.portMatch(tdPort, dport)) \
                       and (self.ipMatch2(tsIp, srange)) and (self.ipMatch2(tdIp, drange)):
                            matched_rule['src'] = tsIp
                            matched_rule['dst'] = tdIp
                            matched_rule['proto'] = rule.protocol
                            matched_rule['target'] = rule.target
                            print "TARGET THING2 " , rule.target
                            return matched_rule

            return matched_rule

