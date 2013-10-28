CSE P 561 Network Systems - Project 1
October 28th, 2013
Jeff Weiner <jdweiner@cs.washington.edu>

Platform used: Python/POX

Performance comparisons:
                  3 hosts         10 hosts
    Hub:        12.2 Mbits/sec  11.5 Mbits/sec
    Switch:     2.88 Gbits/sec  2.76 Gbits/sec

Discussion:

Despite feeling like I already had a good understanding of switching, I learned
a lot with this project.  The devil is really in the details.  The forwarding
table logic needs to be smarter than just "packets to this mac address go out
this port" with a controller-based structure like this, because if it's that
simple, the controller never has a chance to learn about the returning packets
and set up a flow to it.  In essence, only one of the two inbound/outbound
flows would be properly established.

OpenFlow is a really neat framework, and I look forward to building more
detailed controller architectures with it!
