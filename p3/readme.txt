CSE P 561 Network Systems - Project 3 (Network Address Translation)
December 10th, 2013
Jeff Weiner <jdweiner@cs.washington.edu>

Platform used: Python/POX (and the unmodified run_mininet.py harness)

I've developed my NAT to adhere to the following ideas:

* The NAT assumes that the port that is connected to its external interface is
  its highest numbered port.
* If the NAT receives traffic on an internal interface that is not destined
  for the external side of the NAT, then the packet is flooded out every other
  non-external port.  Another way to solve this would be to place a second
  LearningSwitch between the three clients, and the NAT.
* An internal host is always allowed to contact external hosts, but an external
  host is only allowed to contact an internal host through a specific port
  if an internal host has already caused a port in the NAT to be opened for it.
  This is an "endpoint-independent filtering" behavior.
* NAT ports are issued starting from 1024, and will loop back to 1024 after
  port 65535 has been issued.  Records of which port are actively in use are
  kept, and a NAT port will never be used by multiple internal hosts at once.
  They are reused any time a given host tries to communicate with an external
  host, as long as that host uses the same source port number.  This is an
  "endpoint-independent mapping" behavior.
* The NAT will not establish flows with the switch until the TCP connection
  has been observed to have been established.
* In determining if a TCP connection has established, it is not assumed that
  the connectee's SYN will arrive along with an ACK of the connector's SYN.
  This ensures that we can correctly handle TCP Simultaneous Open.
* The "transitory idle" timeout is enforced by my controller, because while we
  enforce using this timeout length, the packets will still be received by the
  controller.  The "established idle" timeout is enforced by the switch,
  because we will have established flows by that point and will not see packets
  past that point.
* The switch will notify the NAT controller when it expires a flow, so that it
  can clean up as necessary.

I did not implement ARP request handling, firewalling, or DHCP, which were the
extra credit options.

This NAT assignment was really useful for demystifying how common household
internet routers work, since most of them perform NAT duties.  I had assumed
that NATing was much more straightforward than it actually turned out to be.
This was a great assignment, and I've really enjoyed this hands-on work
designing packet switching logic. :)
