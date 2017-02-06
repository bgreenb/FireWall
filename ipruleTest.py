from netaddr import *
from IPy import IP
import socket
import re

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

class Comparison(object):
    def __init__(self, table):
        self.table = table

    def portMatch(self, portnum, portRange):
        ports = [int(s) for s in portRange]
        if len(ports) == 0 or portnum == -1:
            return True
        elif len(ports) == 1:
            if portnum == ports[0]:
                return True
        else:
            if portnum >= ports[0] and portnum <= ports[1]:
                return True
        return False

    def isDNS(self,str):
      try:
        IP(str)
      except ValueError:
        return True 
      return False

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
    def groupMatch(self,sIp,dIp,sgroup,dgroup):
        matchSIp = False 
        matchDIp = False

        with open('%s.txt' % sgroup) as sgFile:
          matchSList = [self.ipMatch1(sIp,cmpIp.rstrip()) for cmpIp in sgFile] 
          print "matchSLIST: ", matchSList
          if True in matchSList:
            matchSIp = True
          sgFile.closed

        with open('%s.txt' % dgroup) as dgFile:
          matchDList = [self.ipMatch1(dIp,cmpIp.rstrip()) for cmpIp in dgFile] 
          print "matchDLIST: ", matchDList
          if True in matchDList:
            matchDIp = True
          dgFile.closed

        if matchSIp and matchDIp:
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

