"""
CSE P 561 Network Systems - Project 2 (Load-Balancing Switch)
November 18th, 2013
Jeff Weiner <jdweiner@cs.washington.edu>
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class LoadBalancingSwitch (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L2 load-balancing switch capabilities to
    self.connection= connection
    self.listenTo(connection)

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
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

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LoadBalancingSwitch(event.connection)


def launch ():
  #Starts an L2 load-balancing switch.
  core.registerNew(load_balancing_switch)

