# -*- coding: utf-8 -*
"""
this version support delete a flow after a specific time
and support port match rules
"""
import sys
import os
sys.path.append("/home/bsg/FireWall")

from ryu.base import app_manager
from ryu import cfg
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import ipruleTest
import readRules as rl
import time
import signal
from os.path import expanduser
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS

APP_COOKIE = 0
LIFETIME_ROUTE = 60  #time to delete entries when there are no pkt_in
HARD_LIFETIME = 600  #time to delete entries
PROTOCOLS = {1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp',89:'ospf'}
CONF = cfg.CONF
CONF.register_cli_opts([cfg.StrOpt('Groups',default='Group.conf',help='Group config file location'),cfg.StrOpt('SigFile',default='Group.sig',help='Group signature file location'),cfg.StrOpt('Key',default=expanduser("~")+"/.ssh/id_rsa.pub",help='public key for verifying the config file'),cfg.StrOpt('Rules',default='Rules.txt',help='iptables rules for the controller')])


class MyFireWall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION,ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyFireWall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #self.table = rl.setUp('simpleRulesTest.txt')
        self.table = rl.setUp(self.CONF.Rules)
        self.groupData = ipruleTest.GroupData(self.CONF.Groups) 
        if self.verifyConf(self.CONF.SigFile,self.CONF.Groups,self.CONF.Key):
           print "Group File Signature Verified"
        else:
           print "Group File Signature Verification Failed!"
           noVerify = raw_input("Do you want to continue running the controller?(y/n) ")
           if noVerify != 'y':
              sys.exit()
        self.comparison = ipruleTest.Comparison(self.table,self.groupData)
        signal.signal(signal.SIGHUP,self.signalHandler)

    def signalHandler(self,sigID,frame):
       if sigID == signal.SIGHUP:
          print "Reloading Config File"
          if self.verifyConf(self.CONF.SigFile,self.CONF.Groups,self.CONF.Key):
             print "Group File Signature Verified"
             self.groupData.reload(self.CONF.Groups)
             app_manager.RyuApp.send_event_to_observers(self,ofp_event.EventOFPSwitchFeatures)

          else:
             print "Group File Signature Verification Failed!"
             noVerify = raw_input("Do you want to continue running the controller?(y/n) ")
             if noVerify != 'y':
                sys.exit()
             else:
                self.groupData.reload(self.CONF.Groups)

    def verifyConf(self,sigFile,confFile,keyFile):
       pubKey = RSA.importKey(open(keyFile,'r').read())
       hash = SHA256.new(open(confFile,'r').read())
       if(os.path.isfile(sigFile) == False):
          return False
       signature = open(sigFile).read()
       print "Verifying signature using",sigFile
       verifier = PKCS1_PSS.new(pubKey)
       if verifier.verify(hash,signature):
          return True
       else:
          return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #clean the switch when controller restart
        self.del_flow(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print "Cleared Flow Table"

    def add_flow(self, datapath, priority, match, actions, lifetime=0, hard_time=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=lifetime,
                                hard_timeout=hard_time)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match=None, priority=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            cookie=APP_COOKIE, cookie_mask=APP_COOKIE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=match, priority=priority,
        )
        datapath.send_msg(mod)

    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
               'duration_sec=%d duration_nsec=%d '
               'priority=%d '
               'idle_timeout=%d hard_timeout=%d flags=0x%04x '
               'importance=%d cookie=%d packet_count=%d '
               'byte_count=%d match=%s instructions=%s' %
               (stat.table_id,
                stat.duration_sec, stat.duration_nsec,
                stat.priority,
                stat.idle_timeout, stat.hard_timeout,
                stat.flags, stat.importance,
                stat.cookie, stat.packet_count, stat.byte_count,
                stat.match, stat.instructions))
        self.logger.debug('FlowStats: %s', flows)

    def send_aggregate_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY,ofp.OFPG_ANY,cookie, cookie_mask,match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.debug('AggregateStats: packet_count=%d byte_count=%d '
                         'flow_count=%d',
                         body.packet_count, body.byte_count,
                         body.flow_count)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        pkt_arp = pkt.get_protocols(arp.arp)

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        print "pkt_ip####", pkt_ipv4

        ipProto = None
        dstIp = None
        srcIp = None

        if pkt_ipv4:
#            ip_str = pkt_ipv4[0]
            ipProto = pkt_ipv4.proto
            dstIp = pkt_ipv4.dst
            srcIp = pkt_ipv4.src
            self.logger.info("packet IP info %s %s %s", dstIp, srcIp, ipProto)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        actions_drop = []
        actions_forward = [parser.OFPActionOutput(out_port)]


        if pkt_ipv4:
            #matched_rule = self.comparison.compare(PROTOCOLS[ipProto], srcIp, dstIp)
            #print "matched_rule: ", matched_rule

            if ipProto == 2:
                # for igmp message
                pass

            elif ipProto == 6:
                #tcp pkt
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                print "####pkt_tcp", pkt_tcp

                tcp_sport = pkt_tcp.src_port
                tcp_dport = pkt_tcp.dst_port

                matched_rule = self.comparison.compare(PROTOCOLS[ipProto], srcIp, dstIp, tcp_sport, tcp_dport)
                print "matched_rule: ", matched_rule
                if not matched_rule:
                    return

                if matched_rule['target'] == 'ACCEPT':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto,
                                            tcp_src=tcp_sport, tcp_dst=tcp_dport, eth_type=0x800)
                    time.sleep(0.5)
                    self.add_flow(datapath, 1, match, actions_forward, LIFETIME_ROUTE)
                    #  accept, forward action
                elif matched_rule['target'] == 'DROP':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto,
                                            tcp_src=tcp_sport, tcp_dst=tcp_dport, eth_type=0x800)
                    self.add_flow(datapath, 1, match, actions_drop, LIFETIME_ROUTE)
                else:
                    # for pkts without a matched rule
                    return

            elif ipProto == 17:
                #udp pkt
                pkt_udp = pkt.get_protocol(udp.udp)
                print "####pkt_udp", pkt_udp

                udp_sport = pkt_udp.src_port
                udp_dport = pkt_udp.dst_port

                matched_rule = self.comparison.compare(PROTOCOLS[ipProto], srcIp, dstIp, udp_sport, udp_dport)
                print "matched_rule: ", matched_rule

                if not matched_rule:
                    return

                if matched_rule['target'] == 'ACCEPT':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto,
                                            udp_src=udp_sport, udp_dst=udp_dport, eth_type=0x800)
                    self.add_flow(datapath, 1, match, actions_forward, LIFETIME_ROUTE)
                    #  accept, forward action
                elif matched_rule['target'] == 'DROP':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto,
                                            udp_src=udp_sport, udp_dst=udp_dport, eth_type=0x800)
                    self.add_flow(datapath, 1, match, actions_drop, LIFETIME_ROUTE)
                else:
                    # for pkts without a matched rule
                    return

            else:
                matched_rule = self.comparison.compare(PROTOCOLS[ipProto], srcIp, dstIp)
                print "matched_rule: ", matched_rule

                print "Rule Target %s", matched_rule['target']
                
                if matched_rule['target'] == 'ACCEPT':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto, eth_type=0x800)
                    self.add_flow(datapath, 1, match, actions_forward, LIFETIME_ROUTE)
                    #  accept, forward action
                elif matched_rule['target'] == 'DROP':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto, eth_type=0x800)
                    self.add_flow(datapath, 1, match, actions_drop, LIFETIME_ROUTE)
                else:
                    # for pkts without a matched rule
                    return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        
        datapath.send_msg(out)
        #self.send_flow_stats_request(datapath)
        self.send_aggregate_stats_request(datapath)
        
