"""
CSE P 561 Network Systems - Project 2 (Load-Balancing Switch)
November 18th, 2013
Jeff Weiner <jdweiner@cs.washington.edu>
"""

from datetime import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import *
from pox.lib.addresses import EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import random
import time

log = core.getLogger()

LOADBALANCE_TARGET = "10.123."

def IsMACForLoadBalancing(mac):
  return str(mac).startswith("03:13:37:")

def GetMACForLoadBalancing():
  value = GetMACForLoadBalancing.nextvalue
  GetMACForLoadBalancing.nextvalue += 1
  return EthAddr("031337%06x" % (value & 0xFFFFFF))
GetMACForLoadBalancing.nextvalue = 1

def GetIPFromMAC(mac):
  mactuple = mac.toTuple()
  if mactuple[0:5] == (0,0,0,0,0):
    return "10.0.0.%d" % mactuple[5]
  else:
    return None

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class LoadBalancingSwitch (EventMixin):

  def __init__ (self,connection,hostlocations):
    # Switch we'll be adding L2 load-balancing switch capabilities to
    self.connection= connection
    self.listenTo(connection)
    self.hostlocations = hostlocations
    self.mactable = {}
    self.hostports = {}

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    # If no switch has ever seen this host before, then it must be directly
    # connected to us!  Record that in our global list.
    if packet.src not in self.hostlocations or self.hostlocations[packet.src]["lastseen"] < (datetime.now()-timedelta(0,IDLE_TIMEOUT)):
      #log.debug("s%s takes ownership of host %s" % (self.connection.ID, packet.src))
      self.hostlocations[packet.src] = { "ID": self.connection.ID, "lastseen": datetime.now() }

      # Record which hosts exists on which of our ports
      ip = GetIPFromMAC(packet.src)
      if ip is not None:
        #log.debug("    on IP '%s'" % ip)
        self.hostports[event.port] = packet.src

    elif self.hostlocations[packet.src]["ID"] == self.connection.ID:
      #log.debug("s%s continues to own host %s" % (datetime.now(), self.connection.ID, packet.src))
      self.hostlocations[packet.src]["lastseen"] = datetime.now()

    # Keep a list of which MAC addresses live on which port, so we can forward
    # packets as needed
    if packet.src not in self.mactable or self.mactable[packet.src] != event.ofp.in_port:
        self.mactable[packet.src] = event.ofp.in_port
        #log.debug("Learned port %s connects to %s" % (event.ofp.in_port, packet.src))

    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

    # Watch for ARP packets trying to discover a load-balance target.
    packet_arp = packet.find('arp')
    if packet_arp is not None and str(packet_arp.protodst).startswith(LOADBALANCE_TARGET):
      # Found one!  Respond with a special MAC address, which our switches will
      # be able to identify easily for load-balancing.
      #log.debug('ARP Packet!!!! Looking for %s' % packet_arp.protodst)
      mac = GetMACForLoadBalancing()

      reply_arp = arp()
      reply_arp.hwtype = packet_arp.hwtype
      reply_arp.prototype = packet_arp.prototype
      reply_arp.hwlen = packet_arp.hwlen
      reply_arp.protolen = packet_arp.protolen
      reply_arp.opcode = arp.REPLY
      reply_arp.hwdst = packet_arp.hwsrc
      reply_arp.hwsrc = mac
      reply_arp.protodst = packet_arp.protosrc
      reply_arp.protosrc = packet_arp.protodst
      reply_eth = ethernet(type=packet.type, src=mac, dst=packet_arp.hwsrc)
      reply_eth.payload = reply_arp
      reply = of.ofp_packet_out(in_port=of.OFPP_NONE)
      reply.actions.append(of.ofp_action_output(port=event.port))
      reply.data = reply_eth.pack()
      event.connection.send(reply)
      return

    # If this packet is being delivered to a special MAC, set up some flows to
    # get the data to the right place.
    packet_ipv4 = packet.find('ipv4')
    if IsMACForLoadBalancing(packet.dst) and packet_ipv4 is not None:
      eligibleports = []
      for port in self.connection.features.ports:
        if port.port_no != event.port and not port.config & OFPPC_PORT_DOWN:
          eligibleports.append(port.port_no)
      port_out = random.choice(eligibleports)

      # Establish bi-directional flows!
      log.debug("Establishing load-balancing flows for %s <--> %s" % (packet.src, packet.dst))
      flow_in = of.ofp_flow_mod()
      flow_out = of.ofp_flow_mod()
      flow_in.idle_timeout = flow_out.idle_timeout = IDLE_TIMEOUT
      flow_in.hard_timeout = flow_out.hard_timeout = HARD_TIMEOUT
      flow_in.match = of.ofp_match(dl_dst=packet.src, dl_src=packet.dst)
      flow_out.match = of.ofp_match(dl_dst=packet.dst, dl_src=packet.src)

      if port_out in self.hostports:
        # If we're delivering to a host (instead of another switch), we need
        # to rewrite some of the packet data, so that things line up properly
        # on each end.  The sender sends to the special IP, and the receiver
        # should see the packet addressed to itself (and vice versa).
        log.debug("...which will be handled by %s" % (self.hostports[port_out]))
        flow_in.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, packet.dst))
        flow_in.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, packet_ipv4.dstip))
        flow_out.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, self.hostports[port_out]))
        flow_out.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, GetIPFromMAC(self.hostports[port_out])))

        # We also need to update one of our match rules, since the packet will
        # be sent with a non-special MAC address.
        flow_in.match.dl_src = self.hostports[port_out]

      flow_in.actions.append(of.ofp_action_output(port=event.port))
      flow_out.actions.append(of.ofp_action_output(port=port_out))
      flow_in.in_port = port_out
      flow_out.in_port = event.port
      flow_out.data = event.ofp
      self.connection.send(flow_in)
      self.connection.send(flow_out)
      return

    elif packet.dst in self.mactable:
      # If we know the destination, but are being told about it, recreate the
      # flow, since this is either the initial discovery, or the flow expired.
      log.debug("Establishing flow to deliver packets for %s to port %s" % (packet.dst, self.mactable[packet.dst]))
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

    log.debug("Port for %s unknown -- flooding" % (packet.dst,))
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

class load_balancing_switch (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)
    self.hostlocations = {}

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LoadBalancingSwitch(event.connection, self.hostlocations)


def launch ():
  #Starts an L2 load-balancing switch.
  core.registerNew(load_balancing_switch)

