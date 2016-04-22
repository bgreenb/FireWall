import iptc
import unittest
from netaddr import *


def testPkg(tsPort=-1, tdPort=-1, tsIp=None, tdIp=None ):
    table = iptc.Table(iptc.Table.FILTER)
    for chain in table.chains:
        print "======================="
        print "Chain ", chain.name
        for rule in chain.rules:
            dport = []
            sport = []
            srange = []
            drange = []
            src = rule.src
            dst = rule.dst
            print "Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", \
                rule.dst, "in:", rule.in_interface, "out:", rule.out_interface,
            print "Matches:",
            for match in rule.matches:
                    print match.name,
                    if match.dport != None:
                        dport = match.dport.split(':')
                    if match.sport != None:
                        sport = match.sport.split(':')
                    if match.src_range != None:
                        srange = match.src_range.split('-')
                    if match.dst_range != None:
                        drange = match.dst_range.split('-')
            if ipMatch1(tsIp, src) or ipMatch2(tdIp, dst):
                print "\nTarget:",
                print rule.target.name
                return rule.target.name
            if portMatch(tsPort, sport) or portMatch(tdPort, dport) or ipMatch2(tsIp, srange) or ipMatch2(tdIp, drange):
                print "\nTarget:",
                print rule.target.name
                return rule.target.name
        print "======================="

def portMatch(portnum, portRange):
    ports = [int(s) for s in portRange]
    if len(ports) == 0:
        return False
    elif len(ports) == 1:
        if portnum == ports[0]:
            return True
    else:
        if portnum >= ports[0] and portnum <= ports[1]:
            return True
    return False

def ipMatch2(ip, ipRange):
    if ip == None:
        return False
    if len(ipRange) == 2:
        iprange = IPRange(ipRange[0], ipRange[1])
        if ip in iprange:
            return True
    elif ip == ipRange[0]:
        return True

    return False

def ipMatch1(ip, cmpIP):
    if ip ==None or cmpIP == None or cmpIP == '0.0.0.0/0.0.0.0':
        return False

    if '/' in cmpIP:
        ipset = IPSet([cmpIP])
        if ip in ipset:
            return True
    else:
        if ip == cmpIP:
            return True

#testPkg(10, 22, '192.168.1.3')
class TestIptable(unittest.TestCase):
    """docstring for """
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testPort(self):
        self.assertEqual(testPkg(10,22), 'DROP')

    def testIPrange(self):
        self.assertEqual(testPkg(1,1, '192.168.1.100'), 'DROP')

    def testSubnet(self):
        self.assertEqual(testPkg(1,1, '192.168.0.5'), 'DROP')

if __name__ == '__main__':
    unittest.main()
