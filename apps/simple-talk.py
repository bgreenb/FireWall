from ryu.base import app_manager
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class SimpleTalk(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(SimpleTalk, self).__init__(*args, **kwargs)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        ofp_parser = dp.ofproto_parser

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        dp.send_msg(out)
