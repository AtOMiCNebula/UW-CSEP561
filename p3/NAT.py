"""
CSE P 561 Network Systems - Project 3 (Network Address Translation)
December 10th, 2013
Jeff Weiner <jdweiner@cs.washington.edu>
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

NAT_IP_EXTERNAL = IPAddr("172.64.3.1")

def GetMACFromIP(ip):
  iptuple = tuple((ord(x) for x in ip.toRaw()))
  if iptuple[0:3] == (10, 0, 1):
    num = iptuple[3] - 100
  elif iptuple[0:3] == (172, 64, 3):
    num = iptuple[3] - 20 + 3
  return EthAddr("00:00:00:00:00:%02x" % num)


class NAT (EventMixin):
  def __init__ (self,connection,name):
    self.log = core.getLogger("NAT(%s)" % name)

    # Switch we'll be adding NAT capabilities to
    self.connection = connection
    self.listenTo(connection)
    self.natTable = []
    self.natPorts = {}
    self.natPortNext = 1024

    # Find which port our bridge is on
    ethMax = None
    for p in self.connection.features.ports:
      if ethMax is None or ethMax['name'] < p.name:
        ethMax = { 'name': p.name, 'hw_addr': p.hw_addr, 'port_no': p.port_no }
    self.if_external = ethMax['hw_addr']
    self.port_external = ethMax['port_no']
    self.log.debug("Registered external interface %s on port %s" % (ethMax['hw_addr'], ethMax['name']))

  def IsInternalInterface(self, mac):
    for p in self.connection.features.ports:
      if p.hw_addr == mac:
        return not self.IsExternalInterface(mac)
    return False

  def IsExternalInterface(self, mac):
    return mac == self.if_external

  # Distribute NAT ports according to an endpoint-independent mapping
  def GetNATPort(self, srcip, srcport):
    key = (srcip, srcport)
    if key not in self.natPorts:
      self.natPorts[key] = self.natPortNext
      self.natPortNext += 1
    return self.natPorts[key]

  def _handle_PacketIn (self, event):
    packet = event.parse()
    packet_ipv4 = packet.find('ipv4')
    packet_tcp = packet.find('tcp')

    if self.IsInternalInterface(packet.dst):
      # Look for an existing entry in our NAT table for this connection
      entry = { "src": packet.src, "dst": packet.dst,
                "srcip": packet_ipv4.srcip, "dstip": packet_ipv4.dstip,
                "srcport": packet_tcp.srcport, "dstport": packet_tcp.dstport }
      for row in self.natTable:
        intsc = { k:v for k,v in row.iteritems() if entry.has_key(k) }
        if intsc == entry:
          entry = row
          break
      if entry not in self.natTable:
        # This is a new NAT table entry, so assign a translation port!
        entry["natport"] = self.GetNATPort(entry["srcip"], entry["srcport"])
        self.natTable.append(entry)

      # Create match patterns for outbound and inbound packets
      match_out = of.ofp_match()
      match_out.dl_type = packet.type
      match_out.nw_proto = packet_ipv4.protocol
      match_out.dl_dst = entry["dst"]
      match_out.nw_dst = entry["dstip"]
      match_out.tp_dst = entry["dstport"]
      match_out.dl_src = entry["src"]
      match_out.nw_src = entry["srcip"]
      match_out.tp_src = entry["srcport"]
      match_in = match_out.flip()
      match_in.dl_src = GetMACFromIP(entry["dstip"])
      match_in.dl_dst = self.if_external
      match_in.nw_dst = NAT_IP_EXTERNAL
      match_in.tp_dst = entry["natport"]

      # Create flow rules
      flow_in = of.ofp_flow_mod(match=match_in)
      flow_out = of.ofp_flow_mod(match=match_out)
      flow_in.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, self.if_external))
      flow_in.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, entry["src"]))
      flow_in.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, entry["srcip"]))
      flow_in.actions.append(of.ofp_action_tp_port(of.OFPAT_SET_TP_DST, entry["srcport"]))
      flow_in.actions.append(of.ofp_action_output(port=event.port))
      flow_out.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, self.if_external))
      flow_out.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, NAT_IP_EXTERNAL))
      flow_out.actions.append(of.ofp_action_tp_port(of.OFPAT_SET_TP_SRC, entry["natport"]))
      flow_out.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, GetMACFromIP(entry["dstip"])))
      flow_out.actions.append(of.ofp_action_output(port=self.port_external))
      flow_in.in_port = self.port_external
      flow_out.in_port = event.port
      flow_out.data = event.ofp
      self.connection.send(flow_in)
      self.connection.send(flow_out)

      self.log.debug("New NAT entry: %s:%d -> %s:%d, p=%d" % (entry["srcip"], entry["srcport"], entry["dstip"], entry["dstport"], entry["natport"]))

    elif self.IsExternalInterface(packet.dst):
      self.log.debug("Dropping packet on external interface")


class LearningSwitch (EventMixin):

  def __init__ (self,connection,name):
    self.log = core.getLogger("LearningSwitch(%s)" % name)

    # Switch we'll be adding L2 learning switch capabilities to
    self.connection= connection
    self.listenTo(connection)
    self.mactable = {}

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    # updating out mac to port mapping
    if packet.src not in self.mactable or self.mactable[packet.src] != event.ofp.in_port:
        self.mactable[packet.src] = event.ofp.in_port
        self.log.debug("Port %s connects to %s" % (event.ofp.in_port, packet.src))
    
    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return
    elif packet.dst in self.mactable:
      # If we know the destination, but are being told about it, recreate the
      # flow, since this is either the initial discovery, or the flow expired.
      self.log.debug("Creating flow for %s to port %s" % (packet.dst, self.mactable[packet.dst]))
      fm = of.ofp_flow_mod()
      fm.idle_timeout = IDLE_TIMEOUT
      fm.hard_timeout = HARD_TIMEOUT
      fm.actions.append(of.ofp_action_output(port=self.mactable[packet.dst]))

      # Defining the match via from_packet will cause us to establish a flow
      # for each unique packet type per destination, instead of just per dest.
      fm.match = of.ofp_match(dl_dst=packet.dst, dl_src=packet.src)
      #fm.match = of.ofp_match.from_packet(packet)

      fm.data = event.ofp   # Deliver the packet along this flow
      self.connection.send(fm)
      return

    self.log.debug("Flooding for unknown address %s" % (packet.dst,))
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)


class controller_picker (EventMixin):

  def __init__(self):
    self.log = core.getLogger("Picker")
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    # Determine what switch just came up
    for p in event.connection.features.ports:
      if p.port_no == 65534:
        sw = p.name
    if sw == "sw0":
      constructor = NAT
    else:
      constructor = LearningSwitch

    # Create it!
    self.log.debug("Creating %s(%s)" % (constructor.__name__, sw))
    constructor(event.connection, sw)


def launch ():
  core.registerNew(controller_picker)

