"""
Author Junaid Khalid

This is an L2 learning switch written directly against the OpenFlow library.
It is derived from POX l2_learning.py only for IPv4.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class LearningSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.macToPort = {}
    self.connection= connection
    self.listenTo(connection)
    

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    # updating out mac to port mapping
    self.macToPort[packet.src] = event.port
    
    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

    if packet.dst not in self.macToPort: 
      # does not know out port
      # flood the packet
      log.debug("Port for %s unknown -- flooding" % (packet.dst,))
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    else:
      #installing Flow
      outport = self.macToPort[packet.dst]
      if outport == event.port:
        log.warning("Same port for packet from %s -> %s on %s.  Drop." %
                  (packet.src, packet.dst, outport), dpidToStr(event.dpid))
        return
      log.debug("installing flow for %s.%i -> %s.%i" %
                (packet.src, event.port, packet.dst, outport))
      msg = of.ofp_flow_mod()
      msg.match.dl_src = packet.src
      msg.match.dl_dst = packet.dst
      msg.idle_timeout = IDLE_TIMEOUT
      msg.hard_timeout = HARD_TIMEOUT
      msg.actions.append(of.ofp_action_output(port = outport))
      msg.buffer_id = event.ofp.buffer_id 
      self.connection.send(msg)

class learning_switch (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection)


def launch ():
  #Starts an L2 learning switch.
  core.registerNew(learning_switch)

