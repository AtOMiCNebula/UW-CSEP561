CSE P 561 Network Systems - Project 2 (Load-Balancing Switch)
November 18th, 2013
Jeff Weiner <jdweiner@cs.washington.edu>

Platform used: Python/POX

I've developed my load-balancing switch to adhere to the following ideas:

* If traffic is not sent to the special load-balanced IP region, the switch(es)
  behave like our LearningSwitch from Project 1.
* If traffic is sent to the special load-balanced IP region (10.123.0.0/16),
  it will be sent to a random host within the subnet (excluding the host
  generating the traffic).
* Any host within the subnet is eligible for receiving load-balanced traffic.
  By convention, I've always used the first host created to represent where
  the external traffic is coming from, but I haven't written code to explicitly
  prevent traffic from being sent to it.  It would be trivial to add this, but
  it doesn't add much to the project given our small mininet environments.
* The network should be load-balanced, as well as the hosts.  By this, I mean
  that there is no single point of failure in the network.  No single switch
  determines the entire route, each simply sets up flows to get packets in one
  port and out the next, and each switch is responsible for determine its own
  flows.
* Switches are aware of which hosts are directly connected to it (by loosely
  coordinating with other switches to see if a given switch is the first one to
  "see" a given host), and use this determination to know whether a port is
  connected to another switch, or a host.
* When a host first sends an ARP packet to determine which MAC address has the
  given load-balanced IP, the controller prevents that ARP request from
  propagating any further, and forges a reply with a special MAC address that
  is within a specific range (03:13:37:*:*:*), which allows flows to be more
  easily established.
* When a switch sends data out a port to a load-balanced MAC address, it
  establishes a bi-directional flow to allow packets to be routed more quickly,
  without having to ask the controller for every packet.  The flows are set up
  based only on IPs, and do not take port numbers into consideration (i.e.
  connecting to different ports on the same load-balanced IP will direct you to
  the same host).
* If a switch sends data out a port that it believes a host is on, it
  additionally configures the flow to rewrite the outgoing IP packet such that
  the receiving host sees the packet as directly addressed to its MAC and IP
  addresses.  The switch also configures the opposing flow to undo that rewrite,
  allowing the sender to see the IP and MAC sources it expects to see in its
  replies.
* I assume that every topology is established such that every traversal makes
  forward progress (i.e. there are no loops as long as you don't backtrack).  I
  suppose I could implement spanning-tree protocol, or something like it, but
  felt that was probably out of scope for this project. :)
* I've included a custom topography generator, "treetop", which is idential to
  Mininet's tree topography, with the addition of a host h0 connected to the
  root switch.  I feel this topology most closely resembles the network that
  this would be used in, with h0 representing the gateway to the external
  network.

I've attempted to minimize the amount of hardcoding that was done for this
project.  However, some things were still hardcoded, such as:
* The special MAC address range for load-balancing is [03:13:37:*:*:*].
* The special IP address range for load-balancing is 10.123.0.0/16.
* Hosts must emit some amount of packet traffic on the network, to allow the
  controller and switches to discover their presence.  I addressed this by
  either always starting the controller before mininet, or manually pinging
  hosts through mininet before trying to use load-balancing.
* The non-load-balanced hosts are assumed to have an IP in the 10.0.0.0/24
  range, and a MAC address of [00:00:00:00:00:*], with both of their lowest-
  significance tuples matching (i.e. 10.0.0.127 is on [00:00:00:00:00:7f].
* I have somewhat incomplete support for timing hosts out of the load-balancing
  network.  This would be something that would need to be worked out eventually,
  but given our miniature mininet environment, it wasn't at all necessary.  The
  basis for this is the "lastseen" entry in the global hostlocations dictionary.

I wanted to write a network that was capable of rewriting packets such that the
server/client software did not need to be aware of the load-balanced network.
This was because I didn't want to have to write my own tools to test it, and
also because it felt like the most realistic choice.

Additionally, I tried to minimize how much the controller needed to be
invoked by establishing bi-directional flows upon receiving the first data
packet.  It may be possible to optimize controller invocations beyond a per-flow
basis, but I worried that would compromise my ideal of not having one switch do
all the work (i.e. one switch directing every other switch to establish flows).

Load-balancing traffic across different links would be difficult given my
chosen design.  For starters, the constraint I've imposed that forward progress
always be made by the topography layout prevents there from being multiple
paths to the same host.  I would need to add some way to prevent switching loops
before this would be possible.

Learning the topology on a periodic basis is already somewhat implemented.
Whenever we want to establish a new flow, we check which ports are active, and
will potentially direct traffic out of them.  Additionally, we'll stop
directing traffic if a port goes down.  However, my network design does assume
that at least one host will always be connected to a switch.  If a switch has
no hosts connected, the switch will drop the packet (because it cannot send it
back).

This was a fascinating project.  At many points, I thought something would be
simple, and there ended up being some gotcha.  The one I pulled my hair out the
most over was that the matching rule differed for the inbound flow, if the flow
was leading to a host (because the MAC address we needed to match was the MAC
for that host, and not the special load-balanced one!).  Networks are fun! :)
