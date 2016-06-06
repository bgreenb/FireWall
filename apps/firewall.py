# -*- coding: utf-8 -*
"""
this version support delete a flow after a specific time
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
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import iprule
import readRules as rl

APP_COOKIE = 0
LIFETIME_ROUTE = 60  #time to delete entries when there are no pkt_in
HARD_LIFETIME = 600  #time to delete entries
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

        #clean the switch when controller restart
        self.del_flow(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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
                #tcp pkt
                pkt_tcp = pkt.get_protocol(udp.udp)
                print "####pkt_udp", pkt_udp

                udp_sport = pkt_udp.src_port
                udp_dport = pkt_udp.dst_port

                matched_rule = self.comparison.compare(PROTOCOLS[ipProto], srcIp, dstIp, udp_sport, tcp_dport)
                print "matched_rule: ", matched_rule
                if not matched_rule:
                    return

                if matched_rule['target'] == 'ACCEPT':
                    match = parser.OFPMatch(ipv4_src=srcIp, ipv4_dst=dstIp, ip_proto=ipProto,
                                            udp_src=udp_sport, udp_dst=tcp_dport, eth_type=0x800)
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
