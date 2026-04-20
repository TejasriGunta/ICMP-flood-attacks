"""
icmp_ddos_controller.py
=======================
Adaptive Detection and Graduated Mitigation of ICMP-DDoS Flood Attacks in SDN
Bandi Sathvika (231EC150) & Gunta Tejasri (231ME256), NITK Surathkal

Paper-exact implementation of:
  - Phase 0:  60-second baseline characterisation → μ_F2, σ_F2, T_warn, T_attack
  - Phase 1:  Adaptive sliding window (W=5s, step S adapts with confirmed count)
  - Features: F1 (src entropy), F2 (dst entropy), F3 (type-8 ratio), F4 (pkt-in rate)
  - Detection: two-tier gate: PRIMARY(F2>=T_attack) AND SECONDARY(F3>0.80 OR F4>2×λ)
  - Mitigation: OpenFlow 1.3 meters, 3 levels, quadratic formula Rate=100×(1-c)²
  - Recovery:  hard_timeout on L3 rule → EventOFPFlowRemoved → fresh window eval

Requirements:
    Ryu 4.x, Open vSwitch 2.x, Mininet 2.3+
    pip install ryu

Run:
    ryu-manager icmp_ddos_controller.py --observe-links

Mininet topology (topology.py provided separately):
    h1,h2,h3 → s1 (attackers)   |  h5 → s3 (victim)
    h7,h8,h9 → s2 (legit users) |  s1,s2 → s3 → c3 (controller)
    h4,h6    → s3 (background)
"""

import time
import math
import threading
import collections
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  (all tuneable in one place)
# ─────────────────────────────────────────────────────────────────────────────
class Config:
    # Baseline
    BASELINE_DURATION   = 60        # seconds of clean traffic to profile
    BASELINE_INTERVAL   = 1.0       # sample F2 every N seconds during baseline

    # Sliding window
    W                   = 5         # window width (seconds) — FIXED throughout
    STEP_NORMAL         = W * 0.20  # step when confirmed_count = 0  → 1.00s
    STEP_WARNING        = W * 0.10  # step when confirmed_count = 1  → 0.50s
    STEP_ATTACK         = W * 0.05  # step when confirmed_count >= 2 → 0.25s

    # Detection thresholds
    F3_THRESHOLD        = 0.80      # ICMP type-8 ratio threshold
    # F4: F4_threshold = 2 × λ_pkt_in (computed from baseline)

    # Mitigation
    BASE_RATE           = 100       # pps ceiling for quadratic formula
    HARD_TIMEOUT        = 30        # seconds before L3 rule auto-expires
    INGRESS_SWITCH_DPID = None      # set dynamically to first switch seen
    VICTIM_IP           = "10.0.0.5"
    INGRESS_PORT        = 1         # port on s1 facing h1/h2/h3

    # Packet buffer: how many seconds of packets to keep in rolling buffer
    BUFFER_SECONDS      = W + STEP_NORMAL + 1   # generous margin


# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy_normalized(values):
    """
    Normalized, inverted Shannon entropy of a list of categorical values.
    Returns F2 = 1 − H(X)/log₂(n)  ∈ [0,1]
    High value = concentrated (suspicious); low value = spread (normal).
    Formula from Kumar et al. (SAFETY, 2018) Equations 4–5.
    """
    if not values:
        return 0.0
    counts = collections.Counter(values)
    n = len(counts)
    if n == 1:
        return 1.0           # all packets to one destination → fully suspicious
    total = len(values)
    H = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            H -= p * math.log2(p)
    H_max = math.log2(n)
    return round(1.0 - H / H_max, 6)


def compute_f3(packets):
    """
    F3 = count(type=8) / count(all ICMP)
    Normal ≈ 0.50 (bidirectional). Attack → 1.00 (only requests, no replies).
    Threshold: F3 > 0.80  (paper Table III)
    """
    icmp_pkts = [p for p in packets if p["proto"] == "icmp"]
    if not icmp_pkts:
        return 0.5
    type8 = sum(1 for p in icmp_pkts if p["icmp_type"] == 8)
    return round(type8 / len(icmp_pkts), 4)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CONTROLLER APP
# ─────────────────────────────────────────────────────────────────────────────
class ICMPDDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ── network state ──────────────────────────────────────────────────
        self.datapaths   = {}       # dpid → datapath
        self.mac_to_port = {}       # dpid → {mac → port}

        # ── packet rolling buffer ──────────────────────────────────────────
        # Each entry: {"time": float, "src_ip": str, "dst_ip": str,
        #              "proto": "icmp"|"tcp"|"other", "icmp_type": int|None}
        self.pkt_buffer  = collections.deque()
        self.pkt_lock    = threading.Lock()

        # ── baseline state ─────────────────────────────────────────────────
        self.baseline_done    = False
        self.baseline_samples = []   # F2 values sampled during clean period
        self.mu_F2            = None
        self.sigma_F2         = None
        self.T_warn           = None
        self.T_attack         = None
        self.lambda_pkt_in    = 0.0  # mean packet-in rate during baseline

        # ── detection state ────────────────────────────────────────────────
        self.confirmed_count  = 0
        self.mitigation_level = 0
        self.hard_timeout_at  = None   # sim time when L3 rule expires
        self.next_eval_at     = None   # next window evaluation time

        # ── pkt-in rate tracking ───────────────────────────────────────────
        self.pkt_in_times     = collections.deque()   # timestamps of Packet_In events
        self.baseline_pkt_in_samples = []

        # ── start background thread ────────────────────────────────────────
        self.monitor_thread = hub.spawn(self._monitor_loop)

    # ─────────────────────────────────────────────────────────────────────────
    # OPENFLOW HANDSHAKE
    # ─────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        self.logger.info("[SWITCH] Connected: dpid=%016x", datapath.id)
        self._install_table_miss(datapath)

        # Record first switch as ingress
        if Config.INGRESS_SWITCH_DPID is None:
            Config.INGRESS_SWITCH_DPID = datapath.id
            self.logger.info("[INIT] Ingress switch set to dpid=%016x", datapath.id)

    def _install_table_miss(self, datapath):
        """Table-miss rule: send unknown packets to controller."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, meter_id=None):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = []
        if meter_id:
            inst.append(parser.OFPInstructionMeter(meter_id))
        inst.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            flags=ofp.OFPFF_SEND_FLOW_REM
        )
        datapath.send_msg(mod)

    # ─────────────────────────────────────────────────────────────────────────
    # PACKET_IN HANDLER — records every packet into rolling buffer
    # ─────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        # ── MAC learning & forwarding (basic L2 switch) ────────────────────
        self.mac_to_port[datapath.id][eth_pkt.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(
            eth_pkt.dst, datapath.ofproto.OFPP_FLOOD
        )
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        if out_port != datapath.ofproto.OFPP_FLOOD:
            match = datapath.ofproto_parser.OFPMatch(
                in_port=in_port, eth_dst=eth_pkt.dst
            )
            self._add_flow(datapath, 1, match, actions)
        data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

        # ── record packet into rolling buffer ─────────────────────────────
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        now = time.time()

        entry = {
            "time":      now,
            "src_ip":    ip_pkt.src   if ip_pkt else None,
            "dst_ip":    ip_pkt.dst   if ip_pkt else None,
            "proto":     "icmp"       if icmp_pkt else ("tcp" if ip_pkt and ip_pkt.proto == 6 else "other"),
            "icmp_type": icmp_pkt.type if icmp_pkt else None,
        }
        with self.pkt_lock:
            self.pkt_buffer.append(entry)
            # Record packet-in timestamp for F4
            self.pkt_in_times.append(now)

    # ─────────────────────────────────────────────────────────────────────────
    # FLOW_REMOVED HANDLER — fires when hard_timeout expires
    # ─────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        reason = ev.msg.reason
        ofp    = ev.msg.datapath.ofproto
        if reason == ofp.OFPRR_HARD_TIMEOUT:
            self.logger.info("[TIMEOUT] hard_timeout fired — L3 rule removed. Performing fresh evaluation.")
            self.confirmed_count  = 0
            self.mitigation_level = 0
            self.hard_timeout_at  = None
            # Trigger immediate evaluation on next monitor loop iteration
            self.next_eval_at = 0

    # ─────────────────────────────────────────────────────────────────────────
    # BACKGROUND MONITOR LOOP
    # ─────────────────────────────────────────────────────────────────────────
    def _monitor_loop(self):
        """
        Main state machine:
          Phase 0 (baseline_done=False): collect BASELINE_DURATION seconds,
            derive μ, σ, T_warn, T_attack, λ_pkt_in.
          Phase 1 (baseline_done=True): sliding window detection + mitigation.
        """
        start_time = time.time()
        last_baseline_sample = start_time
        self.logger.info("[BASELINE] Starting %ds baseline characterisation...", Config.BASELINE_DURATION)

        while True:
            now = time.time()

            # ── PHASE 0: BASELINE ─────────────────────────────────────────
            if not self.baseline_done:
                # Sample F2 every BASELINE_INTERVAL seconds
                if now - last_baseline_sample >= Config.BASELINE_INTERVAL:
                    with self.pkt_lock:
                        window_pkts = [
                            p for p in self.pkt_buffer
                            if p["time"] >= now - Config.BASELINE_INTERVAL
                        ]
                    dst_ips = [p["dst_ip"] for p in window_pkts if p["proto"] == "icmp" and p["dst_ip"]]
                    f2 = shannon_entropy_normalized(dst_ips)
                    self.baseline_samples.append(f2)

                    # Sample pkt-in rate
                    with self.pkt_lock:
                        recent_pkt_in = [t for t in self.pkt_in_times if t >= now - Config.BASELINE_INTERVAL]
                        self.baseline_pkt_in_samples.append(len(recent_pkt_in) / Config.BASELINE_INTERVAL)

                    last_baseline_sample = now

                if now - start_time >= Config.BASELINE_DURATION:
                    self._finalise_baseline()

                hub.sleep(0.1)
                continue

            # ── PHASE 1: DETECTION + MITIGATION ──────────────────────────
            # Trim old packets from buffer
            with self.pkt_lock:
                cutoff = now - (Config.W + 2)
                while self.pkt_buffer and self.pkt_buffer[0]["time"] < cutoff:
                    self.pkt_buffer.popleft()
                # Trim old pkt-in timestamps
                while self.pkt_in_times and self.pkt_in_times[0] < now - Config.W:
                    self.pkt_in_times.popleft()

            # Check if it's time to evaluate a window
            if self.next_eval_at is None:
                self.next_eval_at = now + Config.W

            if now >= self.next_eval_at:
                self._evaluate_window(now)
                step = self._get_step()
                self.next_eval_at = now + step
                self.logger.debug("[WINDOW] Next eval in %.2fs (step=%.2f)", step, step)

            hub.sleep(0.05)

    def _finalise_baseline(self):
        """Compute μ, σ, thresholds from collected samples. Paper: Table II."""
        samples = self.baseline_samples
        n = len(samples)
        if n == 0:
            self.logger.error("[BASELINE] No samples collected!")
            return

        self.mu_F2    = sum(samples) / n
        variance      = sum((x - self.mu_F2) ** 2 for x in samples) / n
        self.sigma_F2 = math.sqrt(variance)
        self.T_warn   = self.mu_F2 + 2 * self.sigma_F2
        self.T_attack = self.mu_F2 + 3 * self.sigma_F2

        # F4 baseline: mean pkt-in rate
        pi_samples = self.baseline_pkt_in_samples
        self.lambda_pkt_in = sum(pi_samples) / len(pi_samples) if pi_samples else 10.0

        self.baseline_done = True
        self.logger.info(
            "[BASELINE] DONE — μ_F2=%.4f  σ_F2=%.4f  T_warn=%.4f  T_attack=%.4f  λ_pkt_in=%.2f/s",
            self.mu_F2, self.sigma_F2, self.T_warn, self.T_attack, self.lambda_pkt_in
        )
        self.logger.info("[BASELINE] F4 threshold = 2×λ = %.2f/s", 2 * self.lambda_pkt_in)

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOW EVALUATION — paper Section III-B
    # ─────────────────────────────────────────────────────────────────────────
    def _evaluate_window(self, now):
        """
        Two-tier detection gate (paper Section III-B-3):
          PRIMARY:   F2 >= T_attack
          SECONDARY: F3 > 0.80  OR  F4 > 2×λ_pkt_in
        Both must be true for a window to be confirmed.
        """
        with self.pkt_lock:
            window_pkts = [p for p in self.pkt_buffer if p["time"] >= now - Config.W]
            pkt_in_count = len(self.pkt_in_times)   # already trimmed to W seconds

        # Feature extraction (paper Table III)
        icmp_pkts  = [p for p in window_pkts if p["proto"] == "icmp"]
        dst_ips    = [p["dst_ip"] for p in icmp_pkts if p["dst_ip"]]
        src_ips    = [p["src_ip"] for p in icmp_pkts if p["src_ip"]]

        f1 = shannon_entropy_normalized(src_ips)    # source entropy (reference)
        f2 = shannon_entropy_normalized(dst_ips)    # PRIMARY detection signal
        f3 = compute_f3(window_pkts)                # ICMP type-8 ratio
        f4_rate = pkt_in_count / Config.W           # pkt-in events/sec

        # Two-tier gate
        primary   = f2 >= self.T_attack
        f3_ok     = f3 > Config.F3_THRESHOLD
        f4_ok     = f4_rate > 2 * self.lambda_pkt_in
        secondary = f3_ok or f4_ok

        self.logger.info(
            "[WINDOW] F1=%.3f F2=%.3f F3=%.3f F4=%.1f/s | primary=%s secondary=%s(F3=%s,F4=%s)",
            f1, f2, f3, f4_rate, primary, secondary, f3_ok, f4_ok
        )

        if primary and secondary:
            self._handle_confirmed_window(f2, f3, f4_rate)
        else:
            self._handle_unconfirmed_window(f2, primary, secondary)

    def _handle_confirmed_window(self, f2, f3, f4_rate):
        """Window is confirmed. Increment K, escalate mitigation."""
        self.confirmed_count = min(self.confirmed_count + 1, 3)
        confidence = self.confirmed_count / 3.0
        new_level  = self.confirmed_count

        self.logger.info(
            "[DETECT] Window CONFIRMED  K=%d  F2=%.3f  F3=%.2f  F4=%.1f  c=%.2f",
            self.confirmed_count, f2, f3, f4_rate, confidence
        )

        if new_level > self.mitigation_level:
            self.mitigation_level = new_level
            self._apply_mitigation(new_level, confidence)

    def _handle_unconfirmed_window(self, f2, primary, secondary):
        """Window not confirmed. Check for warning state or full clear."""
        if f2 >= self.T_warn:
            self.logger.info(
                "[WARN] F2=%.3f >= T_warn=%.3f but secondary=%s — Warning State",
                f2, self.T_warn, secondary
            )
        else:
            if self.confirmed_count > 0:
                self.logger.info("[CLEAR] Conditions not met. K reset 0. F2=%.3f", f2)
            self.confirmed_count  = 0
            if self.mitigation_level > 0:
                self._remove_mitigation()

    # ─────────────────────────────────────────────────────────────────────────
    # MITIGATION — paper Section III-C
    # ─────────────────────────────────────────────────────────────────────────
    def _apply_mitigation(self, level, confidence):
        """
        Install/update OpenFlow 1.3 meter on ICMP type=8 packets ONLY.
        Rate formula: Rate = BASE_RATE × (1 - confidence)²   (Equation 1)
        Level 3 sets rate to 0 and installs hard_timeout on the flow rule.

        Meter is placed at the INGRESS switch (s1) — closest to attackers.
        This stops attack traffic at the earliest point, protecting the
        full path to the victim including s3 and h5's NIC.
        """
        if Config.INGRESS_SWITCH_DPID not in self.datapaths:
            self.logger.warning("[MITIGATE] Ingress switch not connected yet.")
            return

        dp     = self.datapaths[Config.INGRESS_SWITCH_DPID]
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        # Quadratic rate formula (paper Equation 1)
        rate_pps = int(Config.BASE_RATE * (1 - confidence) ** 2)
        meter_id = 1  # single meter entry, updated in place

        self.logger.info(
            "[METER L%d] c=%.2f  rate=100×(1-%.2f)²=%d pps  (hard_timeout=%s)",
            level, confidence, confidence, rate_pps,
            str(Config.HARD_TIMEOUT) + "s" if level == 3 else "none"
        )

        # Build meter bands
        if level < 3:
            # Rate limiting: packets over the threshold are DROPPED
            bands = [parser.OFPMeterBandDrop(rate=rate_pps, burst_size=10)]
        else:
            # Level 3: full block (rate=0 → all packets dropped)
            bands = [parser.OFPMeterBandDrop(rate=1, burst_size=0)]

        # Install or modify meter (MODIFY reuses existing without disrupting flows)
        mod_type = ofp.OFPMC_MODIFY if self.mitigation_level > 0 else ofp.OFPMC_ADD
        meter_mod = parser.OFPMeterMod(
            datapath=dp,
            command=mod_type,
            flags=ofp.OFPMF_PKTPS,       # rate in packets/second
            meter_id=meter_id,
            bands=bands
        )
        dp.send_msg(meter_mod)

        # Install flow rule matching ICMP type=8 → victim, directed through meter
        # This is the SURGICAL targeting: type=0 replies are NOT matched,
        # so monitoring tools continue to receive liveness confirmations.
        match = parser.OFPMatch(
            eth_type=0x0800,             # IPv4
            ip_proto=1,                  # ICMP
            icmpv4_type=8,               # Echo Request only
            ipv4_dst=Config.VICTIM_IP
        )
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        hard_to = Config.HARD_TIMEOUT if level == 3 else 0

        self._add_flow(dp, priority=100, match=match, actions=actions,
                       hard_timeout=hard_to, meter_id=meter_id)

        if level == 3:
            self.hard_timeout_at = time.time() + Config.HARD_TIMEOUT
            self.logger.info(
                "[L3] Full block active. Rule will auto-expire in %ds. Self-healing loop engaged.",
                Config.HARD_TIMEOUT
            )

    def _remove_mitigation(self):
        """Remove meter and flow rules. Restore normal forwarding."""
        self.mitigation_level = 0
        self.logger.info("[RECOVER] Attack ceased. Removing meters and flow rules.")
        if Config.INGRESS_SWITCH_DPID not in self.datapaths:
            return
        dp     = self.datapaths[Config.INGRESS_SWITCH_DPID]
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        # Delete meter
        meter_del = parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_DELETE,
            flags=ofp.OFPMF_PKTPS, meter_id=1, bands=[]
        )
        dp.send_msg(meter_del)

        # Delete matching flow rule
        match = parser.OFPMatch(
            eth_type=0x0800, ip_proto=1, icmpv4_type=8,
            ipv4_dst=Config.VICTIM_IP
        )
        flow_del = parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match
        )
        dp.send_msg(flow_del)
        self.logger.info("[RECOVER] Normal traffic fully restored.")

    # ─────────────────────────────────────────────────────────────────────────
    # ADAPTIVE STEP SIZE
    # ─────────────────────────────────────────────────────────────────────────
    def _get_step(self):
        """
        Returns current window step size S based on confirmed_count.
        Paper Section III-B-2 (Table / Figure 3):
          Normal  (K=0): S = W×0.20 = 1.00s
          Warning (K=1): S = W×0.10 = 0.50s
          Attack  (K≥2): S = W×0.05 = 0.25s
        """
        if self.confirmed_count == 0:
            return Config.STEP_NORMAL
        elif self.confirmed_count == 1:
            return Config.STEP_WARNING
        else:
            return Config.STEP_ATTACK
