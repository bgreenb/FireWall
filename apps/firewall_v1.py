# -*- coding: utf-8 -*
"""
this version can parse rules from given file
loop through given iptable rules to insert flows into OF switch
"""
import sys
sys.path.append("/home/kaiyue/FireWall")

from ryu.base import app_manager
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
import iprule
import readRules as rl


PROTOCOLS = {1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp'}

class MyFireWall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(MyFireWall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.table = rl.setUp('../simpleRules.txt')
        self.comparison = iprule.Comparison(self.table)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(dl_dst=addrconv.mac.text_to_bin(dst))
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

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

        pkt_ipv4 = pkt.get_protocols(ipv4.ipv4)
        print "pkt_ip####", pkt_ipv4

        ipProto = None
        dstIp = None
        srcIp = None

        if pkt_ipv4:
            ip_str = pkt_ipv4[0]
            ipProto = ip_str.proto
            dstIp = ip_str.dst
            srcIp = ip_str.src
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
            matched_rule = self.comparison.compare(PROTOCOLS[ipProto], srcIp, dstIp)
            print "matched_rule: ", matched_rule

            if len(matched_rule)==0 or out_port == ofproto.OFPP_FLOOD:
                pass
            elif matched_rule['target'] == 'ACCEPT':
                match = parser.OFPMatch(ipv4_dst=dstIp, eth_type=0x800)
                self.add_flow(datapath, 1, match, actions_forward)
                #  accept, forward action
            else:
                match = parser.OFPMatch(ipv4_dst=dstIp, eth_type=0x800)
                self.add_flow(datapath, 1, match, actions_drop)


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
