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
from pox.openflow.libopenflow_01 import *
from datetime import datetime

TIMEOUT_LEARNINGSWITCH = 30
TIMEOUT_ESTABLISHEDIDLE = 7440
TIMEOUT_TRANSITORYIDLE = 300

NAT_IP_EXTERNAL = IPAddr("172.64.3.1")

def GetMACFromIP(ip):
  iptuple = tuple((ord(x) for x in ip.toRaw()))
  if iptuple[0:3] == (10, 0, 1):
    num = iptuple[3] - 100
  elif iptuple[0:3] == (172, 64, 3):
    num = iptuple[3] - 20 + 3
  return EthAddr("00:00:00:00:00:%02x" % num)

def GetPortFromIP(ip):
  iptuple = tuple((ord(x) for x in ip.toRaw()))
  return iptuple[3] - 100


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
  def GetNATPort(self, intip, intport):
    key = (intip, intport)
    if key not in self.natPorts:
      self.natPorts[key] = self.natPortNext
      self.natPortNext += 1
    return self.natPorts[key]

  # Allow inbound connections according to an endpoint-independent filtering
  def GetInternalMapping(self, natport):
    for key in self.natPorts.iterkeys():
      if self.natPorts[key] == natport:
        return { "ip": key[0], "port": key[1] }
    return None

  # Returns what port number this internal IP is on
  def GetInternalInterfaceFromIP(self, ip):
    iptuple = tuple((ord(x) for x in ip.toRaw()))
    port_no = iptuple[3] - 100
    for p in self.connection.features.ports:
      if p.port_no == port_no:
        return p.hw_addr
    return None

  def _handle_PacketIn (self, event):
    packet = event.parse()
    packet_ipv4 = packet.find('ipv4')
    packet_tcp = packet.find('tcp')

    crossingBoundary = False
    dataGoingOut = False
    entry = None
    if self.IsInternalInterface(packet.dst) or self.IsExternalInterface(packet.dst):
      crossingBoundary = True
      if self.IsInternalInterface(packet.dst):
        entry = { "int": packet.src, "ext": GetMACFromIP(packet_ipv4.dstip),
                  "intip": packet_ipv4.srcip, "extip": packet_ipv4.dstip,
                  "intport": packet_tcp.srcport, "extport": packet_tcp.dstport }
        dataGoingOut = True
      elif self.IsExternalInterface(packet.dst):
        # Check if the NAT knows what this port corresponds to
        mapping = self.GetInternalMapping(packet_tcp.dstport)
        if mapping is not None:
          entry = { "int": GetMACFromIP(mapping["ip"]), "ext": packet.src,
                    "intip": mapping["ip"], "extip": packet_ipv4.srcip,
                    "intport": mapping["port"], "extport": packet_tcp.srcport }
        else:
          self.log.debug("Dropping packet on external interface")

    if entry is not None:
      # Look for an existing entry in our NAT table for this connection
      natTableCleanup = []
      for row in self.natTable:
        if "lastseen" in row and (datetime.now()-row["lastseen"]).seconds > row["timeout"]:
          natTableCleanup.append(row)
        else:
          intsc = { k:v for k,v in row.iteritems() if entry.has_key(k) }
          if intsc == entry:
            entry = row
            break
      for row in natTableCleanup:
        self.natTable.remove(row)

      # From the row we may have found, determine what state the connection
      # establishment is in
      entry["lastseen"] = datetime.now()
      established = False
      if entry not in self.natTable:
        # This is a new NAT table entry, so assign a translation port and
        # record the initial connection state
        entry["natport"] = self.GetNATPort(entry["intip"], entry["intport"])
        entry["outbound"] = dataGoingOut
        entry["intseq" if dataGoingOut else "extseq"] = packet_tcp.seq
        entry["timeout"] = TIMEOUT_TRANSITORYIDLE
        self.natTable.append(entry)
      elif "intacked" not in entry or "extacked" not in entry:
        connector = "int" if entry["outbound"] else "ext"
        connectee = "ext" if entry["outbound"] else "int"
        if packet_ipv4.srcip == (entry["%sip" % connectee]):
          # This is a packet from the connectee
          if not entry.has_key("%sseq" % connectee):
            entry["%sseq" % connectee] = packet_tcp.seq
          if packet_tcp.ack == (entry["%sseq" % connector]+1):
            entry["%sacked" % connectee] = True
        else:
          # This is a packet from the connector
          if packet_tcp.ack and packet_tcp.ack == (entry["%sseq" % connectee]+1):
            entry["%sacked" % connector] = True

        # If we've seen both seq numbers acked, then we're established
        if "intacked" in entry and "extacked" in entry:
          established = True
          entry["timeout"] = TIMEOUT_ESTABLISHEDIDLE

      # Now, pass the data along, or create the flows if we established!
      if not established:
        msg = of.ofp_packet_out()
        self.CreateActions(msg.actions, entry, dataGoingOut)
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)
      else:
        self.CreateFlows(event, packet.type, packet_ipv4.protocol, dataGoingOut, entry)
        self.log.debug("New NAT entry: %s:%d -> %s:%d, p=%d" % (entry["intip"], entry["intport"], entry["extip"], entry["extport"], entry["natport"]))

    if not crossingBoundary:
      # Packet is not trying to cross the NAT boundary
      if event.port != self.port_external:
        # Packet is on the internal side, flood it out internal ports
        msg = of.ofp_packet_out()
        for p in self.connection.features.ports:
          if not p.config & OFPPC_PORT_DOWN and p.port_no not in (event.port, self.port_external):
            msg.actions.append(of.ofp_action_output(port=p.port_no))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

  def CreateFlows(self, event, dl_type, nw_proto, dataGoingOut, entry):
    # Create match patterns for outbound and inbound packets
    match_out = of.ofp_match()
    match_out.dl_type = dl_type
    match_out.nw_proto = nw_proto
    match_out.dl_dst = self.GetInternalInterfaceFromIP(entry["extip"])
    match_out.nw_dst = entry["extip"]
    match_out.tp_dst = entry["extport"]
    match_out.dl_src = entry["int"]
    match_out.nw_src = entry["intip"]
    match_out.tp_src = entry["intport"]
    match_in = match_out.flip()
    match_in.dl_src = GetMACFromIP(entry["extip"])
    match_in.dl_dst = self.if_external
    match_in.nw_dst = NAT_IP_EXTERNAL
    match_in.tp_dst = entry["natport"]

    # Create flow rules
    flow_in = of.ofp_flow_mod(match=match_in)
    flow_out = of.ofp_flow_mod(match=match_out)
    self.CreateActions(flow_in.actions, entry, False)
    self.CreateActions(flow_out.actions, entry, True)
    flow_in.in_port = self.port_external
    flow_out.in_port = GetPortFromIP(entry["intip"])
    (flow_out if dataGoingOut else flow_in).data = event.ofp
    flow_in.idle_timeout = flow_out.idle_timeout = TIMEOUT_ESTABLISHEDIDLE
    self.connection.send(flow_in)
    self.connection.send(flow_out)

  def CreateActions(self, actions, entry, outbound):
    if outbound:
      actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, self.if_external))
      actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, NAT_IP_EXTERNAL))
      actions.append(of.ofp_action_tp_port(of.OFPAT_SET_TP_SRC, entry["natport"]))
      actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, GetMACFromIP(entry["extip"])))
      actions.append(of.ofp_action_output(port=self.port_external))
    else:
      actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, self.if_external))
      actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, entry["int"]))
      actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, entry["intip"]))
      actions.append(of.ofp_action_tp_port(of.OFPAT_SET_TP_DST, entry["intport"]))
      actions.append(of.ofp_action_output(port=GetPortFromIP(entry["intip"])))


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
      fm.idle_timeout = TIMEOUT_LEARNINGSWITCH
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

