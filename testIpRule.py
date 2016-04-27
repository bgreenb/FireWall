import readRules as rl
import unittest
from netaddr import *

def testPkg(table, proto, tsIp=None, tdIp=None, tsPort=-1, tdPort=-1):
    for key in table.chains:
        chain = table.chains[key]
        print "rules in test", len(chain._rules)
        print "======================="
        print "Chain ", chain.name
        for rule in chain._rules:
            dport = []
            sport = []
            srange = []
            drange = []
            src = rule.src
            dst = rule.dst

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

            """
            print "##1", ipMatch1(tsIp, src)
            print '##2', ipMatch1(tdIp, dst)
            print '##3', portMatch(tsPort, sport)
            print '##4', portMatch(tdPort, dport)
            print '##5', ipMatch2(tsIp, srange)
            print '##6',  ipMatch2(tdIp, drange)
            """

            if ipMatch1(tsIp, src) and ipMatch1(tdIp, dst) \
            and portMatch(tsPort, sport) and portMatch(tdPort, dport) \
            and ipMatch2(tsIp, srange) and ipMatch2(tdIp, drange):
                print "Rule", "src:", rule.src, "dst:", \
                    rule.dst, "protocol", rule.protocol
                print "Target:",
                print rule.target
                return rule.target

        print "======================="
    return "QUEUE"

def portMatch(portnum, portRange):
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

# ipMatch1 is used to test -s with ip subnet
def ipMatch1(ip, cmpIP):
    if cmpIP == None or cmpIP == '0.0.0.0/0.0.0.0':
        return True
    if ip ==None:
        return False
    if '/' in cmpIP:
        ipset = IPSet([cmpIP])
        if ip in ipset:
            return True
    else:
        if ip == cmpIP:
            return True

    return False

#ipMatch2 is used to test ipRange
def ipMatch2(ip, ipRange):
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


#testPkg(10, 22, '192.168.1.3')
class TestIptable(unittest.TestCase):
    """docstring for """
    global table
    table = rl.setUp()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_protocol(self):
        self.assertEqual(testPkg(table, 'icmp', '10.1.3.4', '172.31.25.23'), "DROP")

    def test_port(self):
        self.assertEqual(testPkg(table, 'tcp', '192.168.1.100', '172.22.33.106', 10, 22), 'DROP')
        self.assertEqual(testPkg(table, 'tcp', '192.168.1.100', '172.22.33.106', 10, 34), 'QUEUE')

    def test_srcip(self):
        self.assertEqual(testPkg(table, 'udp', '192.168.1.2'), 'DROP')

    def test_subnet(self):
        self.assertEqual(testPkg(table, 'tcp', '10.1.3.4'), 'ACCEPT')

    def test_iprange(self):
        self.assertEqual(testPkg(table, 'tcp', '192.168.1.150', '172.22.33.106', 10, 22), 'DROP')

    def test_normal(self):
        self.assertEqual(testPkg(table, 'tcp', '192.168.5.233', '25.34.23.24'), 'QUEUE')

if __name__ == '__main__':
    unittest.main()
