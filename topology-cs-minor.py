"""
topology.py
===========
Mininet topology matching paper Figure 2:
  s1 (attacker side):  h1, h2, h3
  s2 (legit side):     h7, h8, h9
  s3 (core/victim):    h4, h5 (victim), h6
  c3: Ryu controller

Run:
    sudo python3 topology.py
Then in another terminal:
    ryu-manager icmp_ddos_controller.py --observe-links

Attack (in Mininet CLI):
    h1 hping3 -1 --flood h5 &
    h2 hping3 -1 --flood h5 &
    h3 hping3 -1 --flood h5 &

Legit traffic:
    h7 iperf -s &
    h8 iperf -c 10.0.0.7 -t 300 &
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink


def build_topology():
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoStaticArp=False
    )

    # ── Controller ────────────────────────────────────────────────────────
    c3 = net.addController("c3", controller=RemoteController,
                            ip="127.0.0.1", port=6653)

    # ── Switches ──────────────────────────────────────────────────────────
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")   # core/victim switch

    # ── Attacker hosts (h1-h3) connected to s1 ────────────────────────────
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")

    # ── Background hosts on s3 ────────────────────────────────────────────
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")

    # ── Victim ────────────────────────────────────────────────────────────
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")

    # ── Legitimate users (h7-h9) connected to s2 ─────────────────────────
    h7 = net.addHost("h7", ip="10.0.0.7/24", mac="00:00:00:00:00:07")
    h8 = net.addHost("h8", ip="10.0.0.8/24", mac="00:00:00:00:00:08")
    h9 = net.addHost("h9", ip="10.0.0.9/24", mac="00:00:00:00:00:09")

    # ── Links: 100 Mbps, matching paper spec ─────────────────────────────
    bw = dict(bw=100)

    # Attacker hosts → s1
    net.addLink(h1, s1, **bw)
    net.addLink(h2, s1, **bw)
    net.addLink(h3, s1, **bw)

    # Legit hosts → s2
    net.addLink(h7, s2, **bw)
    net.addLink(h8, s2, **bw)
    net.addLink(h9, s2, **bw)

    # Background + victim → s3
    net.addLink(h4, s3, **bw)
    net.addLink(h5, s3, **bw)
    net.addLink(h6, s3, **bw)

    # Switch interconnects: all converge at s3
    net.addLink(s1, s3, **bw)
    net.addLink(s2, s3, **bw)

    net.build()
    c3.start()
    s1.start([c3])
    s2.start([c3])
    s3.start([c3])

    print("\n=== Topology ready ===")
    print("Attackers:  h1 (10.0.0.1), h2 (10.0.0.2), h3 (10.0.0.3) → s1")
    print("Victim:     h5 (10.0.0.5) → s3")
    print("Legit:      h7-h9 → s2 → s3")
    print("")
    print("Attack commands (run in Mininet CLI):")
    print("  h1 hping3 -1 --flood h5 &")
    print("  h2 hping3 -1 --flood h5 &")
    print("  h3 hping3 -1 --flood h5 &")
    print("")
    print("Measure legitimate TCP:")
    print("  h7 iperf -s &")
    print("  h8 iperf -c 10.0.0.7 -t 300 -i 5 &")
    print("")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_topology()
