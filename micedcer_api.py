#=============================================================================
#
#    MicePRS - Mice (Flows) Physical Routing and Splitting
#
#
#    This is a network application for the Ryu SDN Framework that runs along
#    with a Mininet topology to enable an efficient routing of mice flows.
#
#=============================================================================

__title__ = "MicePRS - Mice (Flows) Physical Routing and Splitting"
__author__ = 'cfamezquita'
__year__ = "2013-2018"

import time
import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, lldp, arp
from ryu.lib.packet import ether_types

#=============================================================================
#
# Main API Class (OpenFlow v1.3)
#
#=============================================================================

_lldpTimeout = 10
_threshold = 60


class MiceDCERApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    #-------------------------------------------------------------------------
    #   * Initialization Process
    #-------------------------------------------------------------------------

    def __init__(self, *args, **kwargs):
        super(MiceDCERApi, self).__init__(*args, **kwargs)

        self.td_network = nx.DiGraph()
        self.td_changes = 0
        self.td_edgepos = {}

        self.cores = []
        self.aggregates = []
        self.edges = []

        self.ports_e2a = {}
        self.ports_a2e = {}
        self.ports_a2c = {}
        self.ports_c2a = {}
        self.ports_to_pod = {}
        self.ports_to_pos = {}

        self.ip_table = {}
        self.vm_table = {}
        self.pending_reqs = []

        self.installed_rules = []

        self.switch_info = {}
        self.init_time = 0
        self.time_table = {}

        # LLDP variables
        self.lldp_neighbors = {}
        self.lldp_level = {}

        self.lldp_timeout = False
        self.lldp_complete = False

    #-------------------------------------------------------------------------
    #   * RYU Event: Switch Features
    #-------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):

        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # Install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        #
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        # Indicates that there is a change in the topology
        dpid = dp.id
        self.td_changes += 1
        self.logger.info("Initialized features for datapath (%s)",
                         self.get_dpid_string(dpid))

    #-------------------------------------------------------------------------
    #   * RYU Event: Switch Enter
    #-------------------------------------------------------------------------

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):

        # Switch Info
        switch = ev.switch
        self.logger.info("\nSwitch Entered: (DPID: %s, Ports: %d)",
                         self.get_dpid_string(switch.dp.id),
                         len(switch.ports))

        # Topology Discovery
        #
        # We get the list of switch and link objects from the topology
        # API and make lists with the main parameters of each component.
        # Then we use the networkx library to update the network graph
        # with the topology data. It is necessary to run the application
        # with --observe-links for this function to work properly.
        #
        # More info at:
        # https://sdn-lab.com/2014/12/31/topology-discovery-with-ryu/
        #
        switch_list = get_switch(self, None)
        links_list = get_link(self, None)

        topo_switches = [s.dp.id for s in switch_list]
        self.td_network.add_nodes_from(topo_switches)

        topo_links1 = [(l.src.dpid, l.dst.dpid, {'port': l.src.port_no})
                       for l in links_list]
        self.td_network.add_edges_from(topo_links1)
        topo_links2 = [(l.dst.dpid, l.src.dpid, {'port': l.dst.port_no})
                       for l in links_list]
        self.td_network.add_edges_from(topo_links2)

        # Initialize LLDP Attributes for Switch
        self.lldp_neighbors.setdefault(switch.dp.id, [])
        self.lldp_level.setdefault(switch.dp.id, 0)
        self.switch_info[switch.dp.id] = {
            'dp': switch.dp,
            'ports': len(switch.ports)
        }

        # Check Topology Changes
        self.td_changes -= 1
        if self.td_changes == 0:
            self.init_time = time.time()
            self.logger.info(
                "\nTopology Discovery complete." +
                "\nWaiting for %s seconds while checking switch layers.",
                _lldpTimeout
            )

    #-------------------------------------------------------------------------
    #   * RYU Event: Switch Leave
    #-------------------------------------------------------------------------

    @set_ev_cls(event.EventSwitchLeave, [
        MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
    ])
    def _switch_leave_handler(self, ev):
        self.logger.info("WARN: Unable to track Switch")

    #-------------------------------------------------------------------------
    #   * RYU Event: Packet-In Handler
    #-------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # Get Message Data
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Handle LLDP packet if LLDP checking is not done
            if not self.lldp_complete:
                self.lldp_packet_handler(msg, pkt)
            return
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            # Handle ARP packet
            self.arp_packet_handler(msg, pkt)
            return
        else:
            # Drop Packet
            return

    #-------------------------------------------------------------------------
    #   * Configure Switch
    #-------------------------------------------------------------------------

    def configure_switch(self, dp):

        # Get Switch Level
        level = self.get_sw_level(dp.id)
        self.logger.info("Level: %s", level)

        # Add Switch to List
        if (level == "EDGE"):
            # Install ARP Rule to Controller
            self.install_rule_arp(dp, 30, "CONTROLLER")
            self.edges.append(dp)
        else:
            # Install ARP Rule to Drop
            self.install_rule_arp(dp, 30)
            if (level == "CORE"):
                self.cores.append(dp)
            elif (level == "AGGREGATE"):
                self.aggregates.append(dp)

    #-------------------------------------------------------------------------
    #   * Configure Topology Ports
    #-------------------------------------------------------------------------

    def configure_topo_ports(self):

        # Initialize Pod for Aggregates
        aggr_pod = {}

        # Edge Switches
        for edge in self.edges:
            links = [link for link in self.td_network.edges()
                     if link[0] == edge.id]
            for l in links:
                src = l[0]
                dst = l[1]
                if self.get_sw_level(dst) == "AGGREGATE":
                    # Get Port of Link from source to destination
                    self.ports_e2a.setdefault(edge.id, [])
                    self.ports_e2a[edge.id].append(
                        self.td_network[src][dst]['port']
                    )

        # Aggregate Switches
        for aggr in self.aggregates:
            ports_pos = {}
            links = [link for link in self.td_network.edges()
                     if link[0] == aggr.id]
            for l in links:
                src = l[0]
                dst = l[1]
                if self.get_sw_level(dst) == "CORE":
                    # Get Port of Link from source to destination
                    self.ports_a2c.setdefault(aggr.id, [])
                    self.ports_a2c[aggr.id].append(
                        self.td_network[src][dst]['port']
                    )
                elif self.get_sw_level(dst) == "EDGE":
                    # Get Port of Link from source to destination
                    self.ports_a2e.setdefault(aggr.id, [])
                    self.ports_a2e[aggr.id].append(
                        (self.td_network[src][dst]['port'], dst)
                    )

                    # Get Pod from Edges
                    if not aggr.id in aggr_pod:
                        aggr_pod[aggr.id] = self.td_edgepos[dst]['pod']

                    # Get Ports to Edge Positions
                    ports_pos.setdefault(self.td_edgepos[dst]['pos'], [])
                    ports_pos[self.td_edgepos[dst]['pos']].append(
                        self.td_network[src][dst]['port'])

            self.ports_to_pos[aggr.id] = ports_pos

        # Core Switches
        for core in self.cores:
            self.ports_to_pod.setdefault(core.id, {})
            links = [link for link in self.td_network.edges()
                     if link[0] == core.id]
            for l in links:
                src = l[0]
                dst = l[1]
                if self.get_sw_level(dst) == "AGGREGATE":
                    # Get Port of Link from source to destination
                    self.ports_c2a.setdefault(core.id, [])
                    self.ports_c2a[core.id].append(
                        (self.td_network[src][dst]['port'], dst)
                    )

                    # Get Ports to Pods
                    self.ports_to_pod[core.id][aggr_pod[dst]] = \
                        self.td_network[src][dst]['port']

        self.logger.info("\nPorts from edges to aggregates:\n%s",
                         self.ports_e2a)
        self.logger.info("\nPorts from aggregates to cores:\n%s",
                         self.ports_a2c)
        self.logger.info("\nPorts from aggregates to edges:\n%s",
                         self.ports_a2e)
        self.logger.info("\nPorts from cores to aggregates:\n%s",
                         self.ports_c2a)
        self.logger.info("\nPorts to pods:\n%s",
                         self.ports_to_pod)

    #-------------------------------------------------------------------------
    #   * Configure Topology Rules
    #-------------------------------------------------------------------------

    def configure_topo_rules(self):

        # Edge Switches
        self.logger.info("\nInstalling rules on edge switches...")
        for edge in self.edges:
            # Create Group Table for Upper Ports
            self.create_group_table(edge, 1, self.ports_e2a[edge.id])
            # Install Edge Switch Rules
            self.install_swrules_edge(edge)

        # Aggregate Switches
        self.logger.info("\nInstalling rules on aggregate switches...")
        for aggr in self.aggregates:
            # Create Group Table for Upper Ports
            self.create_group_table(aggr, 1, self.ports_a2c[aggr.id])
            # Install Aggregate Switch Rules
            self.install_swrules_aggr(aggr)

        # Core Switches
        self.logger.info("\nInstalling rules on core switches...")
        for core in self.cores:
            # Install Core Switch Rules
            self.install_swrules_core(core)

    #-------------------------------------------------------------------------
    #   * LLDP Packet Handler
    #-------------------------------------------------------------------------

    def lldp_packet_handler(self, msg, pkt):

        dp = msg.datapath
        dpid = dp.id

        # Get LLDPDU Information
        #
        # It is obtained as a matrix of objects in tlvs, where
        # position 0 is the Chassis ID object, 1 is the Port ID
        # object, 2 is the TTL object, 3 is the first TLV, 4 is
        # the second TLV and so on. The TLVs are optional and
        # may be inserted in any order. The matrix ends with an
        # End object, which can be obtained by tlvs[-1].
        #
        # To obtain the dpid of the LLDPDU, is needed to get
        # first the information from the Chassis ID. It is a
        # string headed by 'dpid:', so its necessary to replace
        # it with '0x' so it can be parsed easily as a hex value.
        #
        pkt_lldp = pkt.get_protocol(lldp.lldp)
        lldp_tlvs = pkt_lldp.tlvs
        lldp_dpid = int(lldp_tlvs[0].chassis_id.replace('dpid:', '0x'), 16)

        # Get Time from completion of Topology Discovery
        elapsed_time = time.time() - self.init_time

        # Update Neighbor List
        if lldp_dpid not in self.lldp_neighbors[dpid]:
            self.lldp_neighbors[dpid].append(lldp_dpid)
        neighbors = len(self.lldp_neighbors[dpid])

        # Check for Edge Switches
        if elapsed_time > _lldpTimeout:
            if not self.lldp_timeout:
                self.lldp_timeout = True
                self.logger.info("Time for parsing LLDP packets out.")
            if neighbors <= self.switch_info[dpid]['ports'] / 2:
                self.lldp_level[dpid] = 3
                self.logger.info("Switch %s is an edge switch.", dpid)

        # Check for Aggregate Switches
        if self.lldp_level[lldp_dpid] == 3:
            self.lldp_level[dpid] = 2
            self.logger.info("Switch %s is an aggregate switch.", dpid)

        # Check for Core Switches
        if (self.lldp_level[dpid] == 0
        and neighbors == self.switch_info[dpid]['ports']):
            is_core = True
            for sw in self.lldp_neighbors[dpid]:
                if self.lldp_level[sw] != 2:
                    is_core = False
                    break
            if is_core:
                self.lldp_level[dpid] = 1
                self.logger.info("Switch %s is a core switch.", dpid)

        # Check if LLDP Checking is complete
        for dpid, level in list(self.lldp_level.items()):
            self.lldp_complete = True
            if level == 0:
                self.lldp_complete = False
                break

        # Configure Topology
        if self.lldp_complete:
            self.logger.info("\nLLDP switch layer checking complete.")
            self.init_time = time.time()
            for info in list(self.switch_info.values()):
                self.configure_switch(info['dp'])
            self.set_edges_position()
            self.configure_topo_ports()
            self.configure_topo_rules()

    #-------------------------------------------------------------------------
    #   * ARP Packet Handler
    #-------------------------------------------------------------------------

    def arp_packet_handler(self, msg, pkt):

        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        eth_dst = pkt_eth.dst
        eth_src = pkt_eth.src

        pkt_arp = pkt.get_protocol(arp.arp)
        src_mac = pkt_arp.src_mac
        dst_mac = pkt_arp.dst_mac
        src_ip = pkt_arp.src_ip
        dst_ip = pkt_arp.dst_ip

        dpid = dp.id
        timestamp = time.time() - self.init_time

        # Check if packet comes from host
        if (in_port != ofp.OFPP_CONTROLLER
        and in_port not in self.ports_e2a[dpid]):

            # Generate PMAC from source host
            pmac = self.generate_pmac(dpid, in_port, src_mac, src_ip)
            self.ip_table[src_ip] = {
                'dp': dp, 'port': in_port,
                'amac': src_mac, 'pmac': pmac
            }

            # Install rules corresponding to host MAC
            if (dp, src_mac, pmac) not in self.installed_rules:
                self.installed_rules.append((dp, src_mac, pmac))
                self.install_rule_pmac(dp, src_mac, pmac, in_port)

        self.time_table[src_ip] = timestamp

        if pkt_arp.opcode == 1:  # ARP request

            self.logger.info(
                "\nReceived ARP request in datapath (%s), port %s:" +
                "\n%s (%s) -> %s (%s)\n: From (%s) to (%s)" +
                "\n: at time %s",
                dpid, in_port, src_ip, src_mac, dst_ip, dst_mac,
                eth_src, eth_dst, self.get_time_string(timestamp)
            )

            # If the destination IP is unknown by the controller
            if dst_ip not in self.ip_table:

                # Add to list of Pending Requests
                req = {'srcIp': src_ip, 'dstIp': dst_ip}
                if req not in self.pending_reqs:
                    self.pending_reqs.append(req)
                self.logger.info(": Pending requests: %s",
                    self.pending_reqs)

                # Rewrite ARP source MAC (arp_sha) with host PMAC
                actions = [ofp_parser.OFPActionSetField(arp_sha=pmac),
                           ofp_parser.OFPActionOutput(ofp.OFPP_ALL)]
                self.logger.info(": Changed source MAC to PMAC: %s -> %s" +
                                 ": ALL",
                                 src_mac, pmac)
                data = msg.data
                out = ofp_parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=data
                )
                dp.send_msg(out)

                # Generate Request
                e = ethernet.ethernet(src=pmac, dst=eth_dst,
                                      ethertype=ether_types.ETH_TYPE_ARP)
                a = arp.arp(src_mac=pmac, src_ip=src_ip,
                            dst_mac=dst_mac, dst_ip=dst_ip, opcode=1)
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                for edge in self.edges:
                    if edge.id != dpid:
                        # Send Request Packet
                        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_ALL)]
                        out = ofp_parser.OFPPacketOut(
                            datapath=edge, buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=ofp.OFPP_CONTROLLER, actions=actions,
                            data=p.data
                        )
                        edge.send_msg(out)

                        self.logger.info(
                            ": Request generated in datapath (%s) " +
                            "to all ports: \n: %s (%s) -> %s (%s)",
                            edge.id, pmac, src_ip, dst_mac, dst_ip
                        )

            else:
                if (self.time_table[src_ip] - self.time_table[dst_ip]
                > _threshold):

                    # Add to list of Pending Requests
                    req = {'srcIp': src_ip, 'dstIp': dst_ip}
                    if req not in self.pending_reqs:
                        self.pending_reqs.append(req)
                    self.logger.info(": Pending requests: %s",
                        self.pending_reqs)

                    # Rewrite ARP source MAC (arp_sha) with host PMAC
                    actions = [ofp_parser.OFPActionSetField(arp_sha=pmac),
                               ofp_parser.OFPActionOutput(ofp.OFPP_ALL)]
                    self.logger.info(": Changed source MAC to PMAC: %s -> %s" +
                                     ": ALL",
                                     src_mac, pmac)
                    data = msg.data
                    out = ofp_parser.OFPPacketOut(
                        datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions, data=data
                    )
                    dp.send_msg(out)

                    # Generate Check Request
                    e = ethernet.ethernet(src=pmac, dst=eth_dst,
                                          ethertype=ether_types.ETH_TYPE_ARP)
                    a = arp.arp(src_mac=pmac, src_ip=src_ip,
                                dst_mac=dst_mac, dst_ip=dst_ip, opcode=1)
                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)
                    p.serialize()

                    for edge in self.edges:
                        if edge.id != dpid:
                            # Send Request Packet
                            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_ALL)]
                            out = ofp_parser.OFPPacketOut(
                                datapath=edge, buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER, actions=actions,
                                data=p.data
                            )
                            edge.send_msg(out)

                            self.logger.info(
                                ": Check Request generated in datapath (%s) " +
                                "to all ports: \n: %s (%s) -> %s (%s)",
                                edge.id, pmac, src_ip, dst_mac, dst_ip
                            )
                else:

                    dst_pmac = self.ip_table[dst_ip]['pmac']

                    # Generate Reply Packet
                    e = ethernet.ethernet(src=dst_pmac, dst=src_mac,
                                          ethertype=ether_types.ETH_TYPE_ARP)
                    a = arp.arp(src_mac=dst_pmac, src_ip=dst_ip,
                                dst_mac=src_mac, dst_ip=src_ip, opcode=2)
                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)
                    p.serialize()

                    self.logger.info(
                        ": Replied to request in datapath (%s), port %s:" +
                        "\n: %s (%s) -> %s (%s)",
                        dpid, in_port, dst_pmac, dst_ip, src_mac, src_ip
                    )

                    # Send Reply Packet
                    actions = [ofp_parser.OFPActionOutput(in_port)]
                    out = ofp_parser.OFPPacketOut(
                        datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER, actions=actions,
                        data=p.data
                    )
                    dp.send_msg(out)

        elif pkt_arp.opcode == 2:  # ARP reply

            self.logger.info(
                "\nReceived ARP reply in datapath (%s), port %s:" +
                "\n%s (%s) -> %s (%s)" +
                "\n: at time %s",
                dpid, in_port, src_ip, src_mac, dst_ip, dst_mac,
                self.get_time_string(timestamp)
            )

            # Reply to Pending Request
            reqs = [
                req for req in self.pending_reqs
                if req['srcIp'] == dst_ip and req['dstIp'] == src_ip
            ]

            # If IP is in pending request
            if reqs:

                self.pending_reqs.remove({
                    'srcIp': dst_ip, 'dstIp': src_ip
                })

                out_dp = self.ip_table[dst_ip]['dp']
                out_port = self.ip_table[dst_ip]['port']
                out_amac = self.ip_table[dst_ip]['amac']

                # Generate Reply Packet
                e = ethernet.ethernet(src=pmac, dst=out_amac,
                                      ethertype=ether_types.ETH_TYPE_ARP)
                a = arp.arp(src_mac=pmac, src_ip=src_ip,
                            dst_mac=out_amac, dst_ip=dst_ip, opcode=2)
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                self.logger.info(
                    ": Replied to request in datapath (%s), port %s:" +
                    "\n: %s (%s) -> %s (%s)",
                    out_dp.id, out_port, pmac, src_ip, out_amac, dst_ip
                )

                # Send Reply Packet
                actions = [ofp_parser.OFPActionOutput(out_port)]
                out = ofp_parser.OFPPacketOut(
                    datapath=out_dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=ofp.OFPP_CONTROLLER, actions=actions, data=p.data
                )
                out_dp.send_msg(out)

            # Drop packet
            return

    #-------------------------------------------------------------------------
    #   * Install ARP Rule
    #-------------------------------------------------------------------------

    def install_rule_arp(self, dp, priority, output=None):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)

        if not output:
            actions = []
        else:
            if output == "CONTROLLER":
                out_port = ofp.OFPP_CONTROLLER
            elif output == "FLOOD":
                out_port = ofp.OFPP_FLOOD
            elif output == "ALL":
                out_port = ofp.OFPP_ALL
            else:
                out_port = output
            actions = [ofp_parser.OFPActionOutput(out_port)]

        self.add_flow(dp, priority, match, actions)
        self.logger.info("Rule installed on datapath (%s):" +
                         "\n: [ARP] -> %s",
                         self.get_dpid_string(dp.id), output)
        if priority > 0:
            self.logger.info("Priority: *%2d", priority)

    #-------------------------------------------------------------------------
    #   * Install PMAC Rules
    #-------------------------------------------------------------------------

    def install_rule_pmac(self, dp, amac, pmac, port):

        ofp_parser = dp.ofproto_parser

        # Install rule for source MAC change on table 0
        match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    eth_src=amac)
        actions = [ofp_parser.OFPActionSetField(eth_src=pmac)]
        self.add_flow_table(dp, 20, 1, match, actions)

        self.logger.info("Rule installed on datapath (%s) [Table 0]:" +
                         "\n: [IPv4] Src: %s -> eth_src = %s, Table 1",
                         dp.id, amac, pmac)

        # Install rule for source MAC change on table 1
        match = ofp_parser.OFPMatch(eth_dst=pmac)
        actions = [
            ofp_parser.OFPActionSetField(eth_dst=amac),
            ofp_parser.OFPActionOutput(port)
        ]
        self.add_flow(dp, 10, match, actions, 1)

        self.logger.info("Rule installed on datapath (%s) [Table 1]:" +
                         "\n: [IPv4] Dst: %s -> eth_dst = %s, Table 1",
                         dp.id, pmac, amac)

    #-------------------------------------------------------------------------
    #   * Install Rules (Edge Switch)
    #-------------------------------------------------------------------------

    def install_swrules_edge(self, dp):

        ofp_parser = dp.ofproto_parser

        # Install main IPv4 rule on table 0
        match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        self.add_flow_table(dp, 10, 1, match)

        self.logger.info("Rule installed on datapath (%s) [Table 0]:" +
                         "\n: [IPv4] -> Table 1",
                         dp.id)

        # Install table-miss flow entry on table 1
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionGroup(1)]
        self.add_flow(dp, 0, match, actions, 1)

        self.logger.info("Rule installed on datapath (%s) [Table 1]: " +
                         "\n: [Miss] -> Group 1", dp.id)

    #-------------------------------------------------------------------------
    #   * Install Rules (Aggregate Switch)
    #-------------------------------------------------------------------------

    def install_swrules_aggr(self, dp):

        ofp_parser = dp.ofproto_parser

        # Install main IPv4 rule
        match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        actions = [ofp_parser.OFPActionGroup(1)]
        self.add_flow(dp, 10, match, actions)

        self.logger.info("Rule installed on datapath (%s):" +
                         "\n: [IPv4] -> Group 1",
                         dp.id)

        # Rules to Edge Switches
        for port in self.ports_a2e[dp.id]:

            # Get Edge Switch PMAC
            pod = self.td_edgepos[port[1]]['pod']
            pos = self.td_edgepos[port[1]]['pos']
            pmac = self.generate_pmac_wild(pod, pos)
            mask = self.generate_pmac_wild(0xffff, 0xffff)

            # Install Rule to Edge Switch
            match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        eth_dst=(pmac, mask))
            actions = [ofp_parser.OFPActionOutput(port[0])]
            self.add_flow(dp, 20, match, actions)

            self.logger.info("Rule installed on datapath (%s): " +
                             "\n: [IPv4] Dst: (%s, %s) -> Port %s",
                             dp.id, pmac, mask, port[0])

    #-------------------------------------------------------------------------
    #   * Install Rules (Core Switch)
    #-------------------------------------------------------------------------

    def install_swrules_core(self, dp):

        ofp_parser = dp.ofproto_parser

        # Rules to Pods
        for pod, port in list(self.ports_to_pod[dp.id].items()):

            # Get Pod PMAC
            pmac = self.generate_pmac_wild(pod)
            mask = self.generate_pmac_wild(0xffff)

            # Install Rule to Pod
            match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        eth_dst=(pmac, mask))
            actions = [ofp_parser.OFPActionOutput(port)]
            self.add_flow(dp, 20, match, actions)

            self.logger.info("Rule installed on datapath (%s): " +
                             "\n: [IPv4] Dst: (%s, %s) -> Port %s",
                             dp.id, pmac, mask, port)

    #-------------------------------------------------------------------------
    #   * Add Flow
    #-------------------------------------------------------------------------

    def add_flow(self, dp, priority, match, actions, table_id=0):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        mod = ofp_parser.OFPFlowMod(datapath=dp, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id)
        dp.send_msg(mod)

    #-------------------------------------------------------------------------
    #   * Add Flow with Table Instruction
    #-------------------------------------------------------------------------

    def add_flow_table(self, dp, priority, table, match, actions=None,
        table_id=0):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        if actions:
            inst = [
                ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions),
                ofp_parser.OFPInstructionGotoTable(table)
            ]
        else:
            inst = [ofp_parser.OFPInstructionGotoTable(table)]

        mod = ofp_parser.OFPFlowMod(datapath=dp, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id)
        dp.send_msg(mod)

    #-------------------------------------------------------------------------
    #   * Create Group Table
    #-------------------------------------------------------------------------

    def create_group_table(self, dp, group_id, ports):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # Create Buckets
        buckets = []
        for port in ports:
            actions = [ofp_parser.OFPActionOutput(port)]
            bucket = ofp_parser.OFPBucket(1, ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          actions)
            buckets.append(bucket)

        mod = ofp_parser.OFPGroupMod(dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT,
                                     group_id, buckets)
        dp.send_msg(mod)
        self.logger.info("Group %s created on datapath (%s): %s",
                         group_id, dp.id, ports)

    #-------------------------------------------------------------------------
    #   * Set Edge Switches Position
    #-------------------------------------------------------------------------

    def set_edges_position(self):
        for edge in self.edges:
            pod, maxPos = self.check_max_pos_in_pod(edge)
            if maxPos:
                self.td_edgepos[edge.id] = {'pod': pod, 'pos': maxPos + 1}
            else:
                maxPod = self.check_max_pod()
                if maxPod:
                    self.td_edgepos[edge.id] = {'pod': maxPod + 1, 'pos': 1}
                else:
                    self.td_edgepos[edge.id] = {'pod': 1, 'pos': 1}
            self.logger.info("Position set for edge (DPID: %s): %s",
                             self.get_dpid_string(edge.id),
                             self.td_edgepos[edge.id])

    #-------------------------------------------------------------------------
    #   * Check Max Pod in PMAC Table
    #-------------------------------------------------------------------------

    def check_max_pod(self):
        values = []
        for entry in list(self.td_edgepos.values()):
            values.append(entry['pod'])
        return max(values) if values else None

    #-------------------------------------------------------------------------
    #   * Check Max Pos in PMAC Table Pod
    #-------------------------------------------------------------------------

    def check_max_pos_in_pod(self, dp):
        values = []
        nearestEdges = self.get_edges_nearest(dp.id)
        pod = self.get_pod_from_edges(nearestEdges)
        if pod:
            pod_table = [
                entry for entry in list(self.td_edgepos.values())
                if entry['pod'] == pod
            ]
            for entry2 in pod_table:
                values.append(entry2['pos'])
            return pod, max(values)
        else:
            return None, None
        pass

    #-------------------------------------------------------------------------
    #   * Generate Host PMAC
    #-------------------------------------------------------------------------

    def generate_pmac(self, dpid, port, mac, ip):

        # Create entry if does not exist
        if not self.pmac_exists(dpid, port, mac, ip):
            self.vm_table.setdefault((dpid, port), [])
            self.vm_table[(dpid, port)].append((mac, ip))

        # Get Pod, Position (2-byte format) and VM ID
        pod = self.td_edgepos[dpid]['pod'] % 65536
        pos = self.td_edgepos[dpid]['pos'] % 65536
        vmid = self.vm_table[(dpid, port)].index((mac, ip)) + 1

        # Generate PMAC
        pmac = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                   pod / 256, pod % 256, pos / 256, pos % 256,
                   port, vmid
               )

        return pmac

    #-------------------------------------------------------------------------
    #   * Generate PMAC Wildcard
    #-------------------------------------------------------------------------

    def generate_pmac_wild(self, pod, pos=0, port=0, vmid=0):

        # Get Pod, Position (2-byte format), Port and VM ID
        pod = pod % 65536
        pos = pos % 65536
        port = port % 256
        vmid = vmid % 256

        # Generate PMAC
        pmac = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                   pod / 256, pod % 256, pos / 256, pos % 256,
                   port, vmid
               )

        return pmac

    #-------------------------------------------------------------------------
    #   * Conditional: PMAC Exists?
    #-------------------------------------------------------------------------

    def pmac_exists(self, dpid, port, mac, ip):

        # Check if there are entries for switch and port
        if (dpid, port) not in self.vm_table:
            return False

        # Check if VM MAC/IP is in entry table
        if (mac, ip) not in self.vm_table[(dpid, port)]:
            return False

        return True

    #-------------------------------------------------------------------------
    #   * Get Nearest Edge Switches
    #-------------------------------------------------------------------------

    def get_edges_nearest(self, dpid):

        # First Hops
        firstHops = [hop for hop in self.td_network.edges()
                     if hop[0] == dpid]

        # Second Hops
        edges = []
        for h in firstHops:
            edges += [hop[1] for hop in self.td_network.edges()
                     if hop[0] == h[1]
                     and self.get_sw_level(hop[1]) == "EDGE"
                     and hop[1] != dpid]
        return list(set(edges))

    #-------------------------------------------------------------------------
    #   * Get Pod of Set of Edges
    #-------------------------------------------------------------------------

    def get_pod_from_edges(self, edges):
        for dpid in edges:
            if (dpid in self.td_edgepos):
                return self.td_edgepos[dpid]['pod']
        return None

    #-------------------------------------------------------------------------
    #   * Get Datapath ID String
    #-------------------------------------------------------------------------

    def get_dpid_string(self, dpid):

        # Return DPID as String
        return str(dpid)

    #-------------------------------------------------------------------------
    #   * Get Time String
    #-------------------------------------------------------------------------

    def get_time_string(self, timestamp):

        # Return Time String
        return "%dd %02d:%02d\'%02d\"%03d" % (
                timestamp / 60 / 60 / 24,
                timestamp / 60 / 60 % 24,
                timestamp / 60 % 60,
                timestamp % 60,
                timestamp * 1000 % 1000
            )

    #-------------------------------------------------------------------------
    #   * Get Switch Level
    #-------------------------------------------------------------------------

    def get_sw_level(self, dpid):

        # Switch Levels
        levels = {
            1: "CORE",
            2: "AGGREGATE",
            3: "EDGE"
        }

        # Get Key from DPID
        key = self.lldp_level[dpid]
        return levels.get(key, "UNDEFINED")