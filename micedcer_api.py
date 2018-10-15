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
from ryu.lib.packet import ethernet, arp
from ryu.lib.packet import ether_types

#=============================================================================
#
# Main API Class (OpenFlow v1.3)
#
#=============================================================================

_physicSwitch = False


class MicePRSApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    #-------------------------------------------------------------------------
    #   * Initialization Process
    #-------------------------------------------------------------------------

    def __init__(self, *args, **kwargs):
        super(MicePRSApi, self).__init__(*args, **kwargs)

        # Topology Attributes
        self.net = nx.DiGraph()
        self.topo_changes = 0
        self.num_rules = 0
        self.edges_pos = {}
        self.received_flood = []

        # Associations
        self.mac_to_port = {}
        self.ip_to_dp = {}

        # Addressing Lists
        self.ip_list = {}

        # Port Associations
        self.ports_edge_to_aggr = {}
        self.ports_aggr_to_edge = {}
        self.ports_aggr_to_core = {}
        self.ports_core_to_aggr = {}
        self.ports_to_pod = {}
        self.ports_to_pos = {}

        # Group Ports
        self.group_ports = {}

        # Switch Lists
        self.cores = []
        self.aggregates = []
        self.edges = []

        # Show Application Title
        self.showAppTitle()

        self.pmac_table = {}
        self.ip_table = {}
        self.ip_to_mac = {}

        self.received_arp = {}

    #-------------------------------------------------------------------------
    #   * RYU Event Method: Switch Features
    #-------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):

        # Indicate Topology Change
        dpid = ev.msg.datapath.id
        self.topo_changes += 1
        self.logger.info("Initialized features for datapath (%s)",
                         self.getDPIDString(dpid))

    #-------------------------------------------------------------------------
    #   * RYU Event Method: Switch Enter
    #-------------------------------------------------------------------------

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):

        # Get Switch Info
        switch = ev.switch
        self.logger.info("\nSwitch Entered: (DPID: %s, Ports: %d)",
                         self.getDPIDString(switch.dp.id), len(switch.ports))

        # Topology Discovery
        switch_list = get_switch(self, None)
        links_list = get_link(self, None)

        topo_switches = [s.dp.id for s in switch_list]
        self.net.add_nodes_from(topo_switches)
        topo_links1 = [(l.src.dpid, l.dst.dpid, {'port': l.src.port_no})
                       for l in links_list]
        self.net.add_edges_from(topo_links1)
        topo_links2 = [(l.dst.dpid, l.src.dpid, {'port': l.dst.port_no})
                       for l in links_list]
        self.net.add_edges_from(topo_links2)

        # Configure Switch
        self.configureSwitch(switch.dp)

        # Check Topology Changes
        self.topo_changes -= 1
        if self.topo_changes == 0:
            self.logger.info("\nTopology Discovery complete.")
            self.setEdgesPosition()
            self.setPorts()
            self.installSwitchRules()
            self.logger.info("\n\nTotal number of rules: %d", self.num_rules)

    #-------------------------------------------------------------------------
    #   * RYU Event Method: Switch Leave
    #-------------------------------------------------------------------------

    @set_ev_cls(event.EventSwitchLeave, [
        MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
    ])
    def _switch_leave_handler(self, ev):
        self.logger.info("WARN: Unable to track Switch")

    #-------------------------------------------------------------------------
    #   * RYU Event Method: Host Add
    #-------------------------------------------------------------------------

    @set_ev_cls(event.EventHostAdd)
    def _host_add_handler(self, ev):

        host = ev.host  # Get Host Info

        dpid = host.port.dpid
        port_no = host.port.port_no
        host_mac = host.mac
        host_ip = host.ipv4[0]

        self.logger.info("\nHost Added: (MAC: %s, IP: %s)", host_mac, host_ip)
        self.logger.info("for datapath (%s, port %s)",
                         self.getDPIDString(dpid), port_no)

        # Set (Virtual) Host PMAC
        self.setHostPMAC(dpid, port_no, host_mac, host_ip)

    #-------------------------------------------------------------------------
    #   * RYU Event Method: Packet-In
    #-------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # Main Packet Info
        msg = ev.msg
        dp = msg.datapath
        if msg.msg_len < msg.total_len:
            self.logger.info(
                "Packet truncated in datapath (%s): only %s of %s bytes",
                self.getDPIDString(dp.id), msg.msg_len, msg.total_len
            )

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packet
            return
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.checkARPAddress(dp, pkt, eth.src, eth.dst, in_port)
            return

        dst = eth.dst
        src = eth.src

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("\nPacket in datapath (%s), port %s: %s -> %s",
                         dpid, in_port, src, dst)

        # Learn a MAC address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofp.OFPP_FLOOD:
            match = ofp_parser.OFPMatch(in_port=in_port,
                    eth_dst=dst, eth_src=src)
            # Verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self.add_flow(dp, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(dp, 1, match, actions)
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions,
                                      data=data)
        dp.send_msg(out)

    #-------------------------------------------------------------------------
    #   * Add Flow
    #-------------------------------------------------------------------------

    def add_flow(self, dp, priority, match, actions, buffer_id=None):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        if buffer_id:
            mod = ofp_parser.OFPFlowMod(datapath=dp, priority=priority,
                                        match=match, instructions=inst,
                                        buffer_id=buffer_id)
        else:
            mod = ofp_parser.OFPFlowMod(datapath=dp, priority=priority,
                                        match=match, instructions=inst)
        dp.send_msg(mod)

    #-------------------------------------------------------------------------
    #   * Delete Flow
    #-------------------------------------------------------------------------

    def del_flow(self, dp, match):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        mod = ofp_parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                match=match)
        dp.send_msg(mod)

    #-------------------------------------------------------------------------
    #   * Configure Switch
    #-------------------------------------------------------------------------

    def configureSwitch(self, dp):

        ofp = dp.ofproto

        # Get Switch Level
        level = self.getLevel(dp.id)
        self.logger.info("Level: %s", level)

        # Install ARP Action Rules
        if (level == "EDGE"):
            self.installARPActionRule(dp, ofp.OFPP_CONTROLLER, 4)
            self.edges.append(dp)
        else:
            self.installARPActionRule(dp, ofp.OFPP_FLOOD, 4)
            if (level == "CORE"):
                self.cores.append(dp)
            elif (level == "AGGREGATE"):
                self.aggregates.append(dp)

    #-------------------------------------------------------------------------
    #   * Set Edge Switches Position
    #-------------------------------------------------------------------------

    def setEdgesPosition(self):

        for edge in self.edges:
            pod, maxPos = self.checkMaxPosInPod(edge)
            if maxPos:
                self.edges_pos[edge.id] = {'pod': pod, 'pos': maxPos + 1}
            else:
                maxPod = self.checkMaxPodInTable()
                if maxPod:
                    self.edges_pos[edge.id] = {'pod': maxPod + 1, 'pos': 1}
                else:
                    self.edges_pos[edge.id] = {'pod': 1, 'pos': 1}
            self.logger.info("Position set for edge (DPID: %s): %s",
                             self.getDPIDString(edge.id),
                             self.edges_pos[edge.id])

    #-------------------------------------------------------------------------
    #   * Set (Virtual) Host PMAC
    #-------------------------------------------------------------------------

    def setHostPMAC(self, dpid, port_no, host_mac, host_ip):

        # Store VM IP address for Host
        self.ip_table.setdefault(host_mac, [])
        if host_ip not in self.ip_table[host_mac]:
            self.ip_table[host_mac].append(host_ip)

        pod, pos = self.checkInTable(dpid)
        vmid = self.ip_table[host_mac].index(host_ip) + 1

        self.pmac_table.setdefault(host_mac, {})

        # Generate Virtual Host PMAC
        pmac = self.getPMAC(pod, pos, port_no, vmid)
        self.pmac_table[host_mac][host_ip] = pmac
        self.logger.info("PMAC assigned for host: %s",
                         self.pmac_table[host_mac][host_ip])

    #-------------------------------------------------------------------------
    #   * Set Ports
    #-------------------------------------------------------------------------

    def setPorts(self):

        # Initialize Pod for Aggregates
        aggr_pod = {}

        # Edge Switches
        for edge in self.edges:
            links = [link for link in self.net.edges() if link[0] == edge.id]
            ports = []
            for l in links:
                if self.getLevel(l[1]) == "AGGREGATE":
                    ports.append(self.net[l[0]][l[1]]['port'])
            self.ports_edge_to_aggr[edge.id] = ports

        # Aggregate Switches
        for aggr in self.aggregates:
            links = [link for link in self.net.edges() if link[0] == aggr.id]
            ports_edge = []
            ports_core = []
            ports_pos = {}
            for l in links:
                if self.getLevel(l[1]) == "EDGE":
                    ports_edge.append(self.net[l[0]][l[1]]['port'])
                    # Get Pod from Edges
                    if not aggr.id in aggr_pod:
                        aggr_pod[aggr.id] = self.edges_pos[l[1]]['pod']
                    # Get Pos from Edges
                    ports_pos.setdefault(self.edges_pos[l[1]]['pos'], [])
                    ports_pos[self.edges_pos[l[1]]['pos']].append(
                        self.net[l[0]][l[1]]['port'])
                elif self.getLevel(l[1]) == "CORE":
                    ports_core.append(self.net[l[0]][l[1]]['port'])
            self.ports_aggr_to_edge[aggr.id] = ports_edge
            self.ports_aggr_to_core[aggr.id] = ports_core
            self.ports_to_pos[aggr.id] = ports_pos

        # Core Switches
        for core in self.cores:
            links = [link for link in self.net.edges() if link[0] == core.id]
            ports_aggr = []
            ports_pod = {}
            for l in links:
                if self.getLevel(l[1]) == "AGGREGATE":
                    ports_aggr.append(self.net[l[0]][l[1]]['port'])
                    # Get Pod from Aggragates
                    ports_pod.setdefault(aggr_pod[l[1]], [])
                    ports_pod[aggr_pod[l[1]]].append(
                        self.net[l[0]][l[1]]['port'])
            self.ports_core_to_aggr[core.id] = ports_aggr
            self.ports_to_pod[core.id] = ports_pod

        self.logger.info("\nPorts from edges to aggregates:\n%s",
                         self.ports_edge_to_aggr)
        self.logger.info("\nPorts from aggregates to edges:\n%s",
                         self.ports_aggr_to_edge)
        self.logger.info("\nPorts from aggregates to cores:\n%s",
                         self.ports_aggr_to_core)
        self.logger.info("\nPorts from cores to aggregates:\n%s",
                         self.ports_core_to_aggr)
        self.logger.info("\nPorts to pods:\n%s",
                         self.ports_to_pod)

    #-------------------------------------------------------------------------
    #   * Set Group Action
    #-------------------------------------------------------------------------

    def setGroupAction(self, dp, group_id, ports):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buckets = []

        for port in ports:
            actions = [ofp_parser.OFPActionOutput(port)]
            bucket = ofp_parser.OFPBucket(1, ofp.OFPP_ANY, ofp.OFPG_ANY,
                                          actions)
            buckets.append(bucket)

        mod = ofp_parser.OFPGroupMod(dp, ofp.OFPGC_ADD, ofp.OFPGT_FF,
                                     group_id, buckets)
        dp.send_msg(mod)

        # Store Group Ports
        self.group_ports.setdefault(dp.id, {})
        self.group_ports[dp.id][group_id] = ports

    #-------------------------------------------------------------------------
    #   * Install Switch Rules
    #-------------------------------------------------------------------------

    def installSwitchRules(self):

        self.logger.info("\nInstalling Rules...")

        # Core Switches
        for core in self.cores:
            # Rules to Pods
            pods = self.checkMaxPodInTable()
            for p in range(pods):
                pmac = self.getPMAC(p + 1, 0, 0, 0)
                mask = self.getPMAC(0xffff, 0, 0, 0)
                self.setGroupAction(core, p + 1,
                                    self.ports_to_pod[core.id][p + 1])
                self.installRuleGroup(core, ["MAC", (pmac, mask)], p + 1, 1)

        # Aggregate Swithes
        for aggr in self.aggregates:
            # Rules to Cores
            self.setGroupAction(aggr, 0, self.ports_aggr_to_core[aggr.id])
            self.installRuleGroup(aggr, ["*"], 0, 1)
            # Rules to Edges
            links = [link for link in self.net.edges()
                     if link[0] == aggr.id
                     and self.getLevel(link[1]) == "EDGE"]
            for l in links:
                pod = self.edges_pos[l[1]]['pod']
                pos = self.edges_pos[l[1]]['pos']
                pmac = self.getPMAC(pod, pos, 0, 0)
                mask = self.getPMAC(0xffff, 0xffff, 0, 0)
                self.setGroupAction(aggr, pos,
                                    self.ports_to_pos[aggr.id][pos])
                self.installRuleGroup(aggr, ["MAC", (pmac, mask)], pos, 1)

        # Edge Switches
        for edge in self.edges:
            # Rules to Aggregates
            self.setGroupAction(edge, 0, self.ports_edge_to_aggr[edge.id])
            self.installRuleGroup(edge, ["*"], 0, 1)
            # Rules to Hosts
            pod = self.edges_pos[edge.id]['pod']
            pos = self.edges_pos[edge.id]['pos']
            pmac = self.getPMAC(pod, pos, 0, 0)
            mask = self.getPMAC(0xffff, 0xffff, 0, 0)
            self.installRule(edge, ["MAC", (pmac, mask)],
                             edge.ofproto.OFPP_CONTROLLER, 1)

    #-------------------------------------------------------------------------
    #   * Check Entry in PMAC Table
    #-------------------------------------------------------------------------

    def checkInTable(self, dpid):
        if dpid in list(self.edges_pos.keys()):
            entry = self.edges_pos[dpid]
            return entry['pod'], entry['pos']
        else:
            return None, None

    #-------------------------------------------------------------------------
    #   * Check Max Pod in PMAC Table
    #-------------------------------------------------------------------------

    def checkMaxPodInTable(self):
        values = []
        for entry in list(self.edges_pos.values()):
            values.append(entry['pod'])
        return max(values) if values else None

    #-------------------------------------------------------------------------
    #   * Check Max Pos in PMAC Table Pod
    #-------------------------------------------------------------------------

    def checkMaxPosInPod(self, dp):
        values = []
        nearestEdges = self.getNearestEdgeSwitches(dp.id)
        pod = self.getPod(nearestEdges)
        if pod:
            pod_table = [
                entry for entry in list(self.edges_pos.values())
                if entry['pod'] == pod
            ]
            for entry2 in pod_table:
                values.append(entry2['pos'])
            return pod, max(values)
        else:
            return None, None
        pass

    #-------------------------------------------------------------------------
    #   * Check Destination Address In ARP Message
    #-------------------------------------------------------------------------

    def checkARPAddress(self, dp, pkt, src, dst, in_port):

        dpid = dp.id
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        arp_pkt = pkt.get_protocols(arp.arp)[0]
        in_dmac, in_dip = arp_pkt.dst_mac, arp_pkt.dst_ip
        in_smac, in_sip = arp_pkt.src_mac, arp_pkt.src_ip

        # Check if FLOOD or Direct Request message
        flood = True if in_dmac == 'ff:ff:ff:ff:ff:ff' else False
        dir_req = True if in_dmac == '00:00:00:00:00:00' else False

        # Avoid switch to receive again same FLOOD message
        key = (dpid, in_smac, in_sip, in_dip)
        if flood or dir_req:
            if key in self.received_flood:
                return
            else:
                self.received_flood.append(key)

        # Incoming Packet Info
        arp_type = "Request" if arp_pkt.opcode == 1 else "Reply"
        arp_src = "{0} [{1}]".format(in_smac, in_sip)
        arp_dst = "{0} [{1}]".format(in_dmac, in_dip)
        self.logger.info("\nARP Packet in datapath (%s), port %s: %s -> %s",
                         dp.id, in_port, src, dst)
        self.logger.info("%s: %s -> %s", arp_type, arp_src, arp_dst)

        # Learn MAC and IP address to avoid FLOOD next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        self.ip_list.setdefault(dpid, [])
        self.ip_list[dpid].append(in_sip)

        # Associate Direct IP with Switch
        if dir_req:
            if not in_sip in self.ip_to_dp:     # New IP Association
                self.ip_to_dp[in_sip] = dp
                self.installRule(dp, ["MAC", src], in_port, 2)
            elif dp != self.ip_to_dp[in_sip]:   # Update IP Association
                self.ip_to_dp[in_sip] = dp
        elif not flood and arp_pkt.opcode == 2:
            if not in_sip in self.ip_to_dp:     # New IP Association
                self.ip_to_dp[in_sip] = dp
                self.installRule(dp, ["MAC", src], in_port, 2)
            elif dp != self.ip_to_dp[in_sip]:   # Update IP Association
                self.ip_to_dp[in_sip] = dp

        if in_dip in self.ip_list[dpid]:
            if arp_pkt.opcode == 1:
                # Reply Back Message
                self.logger.info("Reply Back")
                opcode = 2
                out_smac, out_sip = in_dmac, in_dip
                out_dmac, out_dip = in_smac, in_sip
                out_dp = dp
                out_port = in_port
            else:
                # Reply Message
                self.logger.info("Forward Reply")
                opcode = 2
                out_smac, out_sip = in_smac, in_sip
                out_dmac, out_dip = in_dmac, in_dip
                out_dp = self.ip_to_dp[in_dip]
                out_port = self.mac_to_port[out_dp.id][in_dmac]
        else:
            # FLOOD message
            opcode = 1
            out_smac, out_sip = in_smac, in_sip
            out_dmac, out_dip = 'ff:ff:ff:ff:ff:ff', in_dip
            out_dp = dp
            out_port = ofp.OFPP_FLOOD

        # Outgoing Packet Info
        if out_dp.id != dpid:
            msg_port = ofp.OFPP_CONTROLLER
            mfrom = "Controller"
        else:
            msg_port = in_port
            mfrom = "Port {0}".format(in_port)
        self.logger.info("Packet in datapath (%s) from %s:", out_dp.id, mfrom)

        if out_port == ofp.OFPP_FLOOD:
            self.logger.info("FLOOD")
        else:
            self.logger.info("%s [%s] -> %s [%s], port %s",
                             out_smac, out_sip, out_dmac, out_dip, out_port)

        # Generate Packet
        e = ethernet.ethernet(dst, src, ether_types.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=opcode,
            src_mac=out_smac, src_ip=out_sip,
            dst_mac=out_dmac, dst_ip=out_dip)
        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        # Send Packet
        actions = [ofp_parser.OFPActionOutput(out_port)]

        out = ofp_parser.OFPPacketOut(datapath=out_dp,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=msg_port, actions=actions,
                                      data=pkt.data)
        dp.send_msg(out)

    #-------------------------------------------------------------------------
    #   * Install Rule
    #-------------------------------------------------------------------------

    def installRule(self, dp, field, output, priority=0):

        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        actions = [ofp_parser.OFPActionOutput(output)]

        if field[0] == "ARP":
            if output == ofp.OFPP_CONTROLLER:
                rule = "ARP -> CONTROLLER"
            elif output == ofp.OFPP_FLOOD:
                rule = "ARP -> FLOOD"
            else:
                rule = "ARP -> ({0})".format(output)
            if len(field) > 1:
                match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                            in_port=field[1],
                                            eth_src=field[2], eth_dst=field[3])
            else:
                match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)

        else:
            if len(field) == 2:
                rule = "(* -> {1}) -> Port {0}".format(output, field[1])
                match = ofp_parser.OFPMatch(eth_dst=field[1])
            elif len(field) == 3:
                rule = "({2} -> {1}) -> Port {0}".format(
                        output, field[1], field[2])
                match = ofp_parser.OFPMatch(eth_src=field[2], eth_dst=field[1])
            else:
                rule = "Port {3} ({2} -> {1}) -> Port {0}".format(
                        output, field[1], field[2], field[3])
                match = ofp_parser.OFPMatch(in_port=field[3],
                                            eth_src=field[2], eth_dst=field[1])

        self.logger.info("Rule installed on datapath (%s): %s",
                         self.getDPIDString(dp.id), rule)

        self.add_flow(dp, priority, match, actions)
        self.num_rules += 1

    #-------------------------------------------------------------------------
    #   * Install Rule Group
    #-------------------------------------------------------------------------

    def installRuleGroup(self, dp, field, group_id, priority=0):

        ofp_parser = dp.ofproto_parser

        actions = [ofp_parser.OFPActionGroup(group_id)]

        if len(field) == 1:
            rule = "(* -> *) -> Group {0}".format(group_id)
            match = ofp_parser.OFPMatch()
        elif len(field) == 2:
            rule = "(* -> {1}) -> Group {0}".format(group_id, field[1])
            match = ofp_parser.OFPMatch(eth_dst=field[1])
        elif len(field) == 3:
            rule = "({2} -> {1}) -> Group {0}".format(
                    group_id, field[1], field[2])
            match = ofp_parser.OFPMatch(eth_src=field[2], eth_dst=field[1])
        else:
            rule = "Port {3} ({2} -> {1}) -> Group {0}".format(
                    group_id, field[1], field[2], field[3])
            match = ofp_parser.OFPMatch(in_port=field[3],
                                        eth_src=field[2], eth_dst=field[1])

        self.logger.info("Rule installed on datapath (%s): %s %s",
                         self.getDPIDString(dp.id), rule,
                         self.group_ports[dp.id][group_id])

        self.add_flow(dp, priority, match, actions)
        self.num_rules += 1

    #-------------------------------------------------------------------------
    #   * Install ARP Action Rule
    #-------------------------------------------------------------------------

    def installARPActionRule(self, dp, action, priority=0):
        self.installRule(dp, ["ARP"], action, priority)

    #-------------------------------------------------------------------------
    #   * Get Nearest Edge Switches
    #-------------------------------------------------------------------------

    def getNearestEdgeSwitches(self, dpid):

        edges = []
        aggr = [link for link in self.net.edges() if link[0] == dpid]
        for l in aggr:
            # Get Nearest Edge Switches
            edges += [link[1] for link in self.net.edges()
                     if link[0] == l[1]
                     and self.getLevel(link[1]) == "EDGE"
                     and link[1] != dpid]
        return list(set(edges))

    #-------------------------------------------------------------------------
    #   * Get Switch Level
    #-------------------------------------------------------------------------

    def getLevel(self, dpid):

        key_to_level = {
            1: "CORE",
            2: "AGGREGATE",
            3: "EDGE"
        }
        if _physicSwitch:  # Key varies in physic switch
            key = (dpid >> 48) / 1000
        else:
            key = (dpid) / 1000
        lvl = key_to_level.get(key, "UNDEFINED")
        return lvl

    #-------------------------------------------------------------------------
    #   * Get Pod of Set of Edges
    #-------------------------------------------------------------------------

    def getPod(self, edges):
        for dpid in edges:
            if (dpid in self.edges_pos):
                return self.edges_pos[dpid]['pod']
        return None

    #-------------------------------------------------------------------------
    #   * Get PMAC from Parameters
    #-------------------------------------------------------------------------

    def getPMAC(self, pod, pos=-1, port=-1, vmid=-1):
        pmac = "{:02x}".format(pod / 256) \
            + (":{:02x}".format(pod % 256)) \
            + (":{:02x}".format(pos / 256) if pos >= 0 else ':**') \
            + (":{:02x}".format(pos % 256) if pos >= 0 else ':**') \
            + (":{:02x}".format(port % 256) if port >= 0 else ':**') \
            + (":{:02x}".format(vmid % 256) if vmid >= 0 else ':**')
        return pmac

    #-------------------------------------------------------------------------
    #   * Get AMAC from Switch PMAC
    #-------------------------------------------------------------------------

    def getAMACFromPMAC(self, pmac):
        pass

    #-------------------------------------------------------------------------
    #   * Get Datapath ID String
    #-------------------------------------------------------------------------

    def getDPIDString(self, dpid):
        if _physicSwitch:
            return "{:16x}".format(dpid)
        else:
            return str(dpid)

    #-------------------------------------------------------------------------
    #   * Show App Title
    #-------------------------------------------------------------------------

    def showAppTitle(self):
        self.logger.info("\n%s\n%s %s\n", __title__, __year__, __author__)