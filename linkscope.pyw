"""LinkScope - see what is actually on each Ethernet cable, and why ping fails.

Shows every network adapter with its IPv4 setup, passively listens on each
wired adapter with tshark (Npcap, no admin needed), lists every device heard
on the cable with the IPs it uses, and explains in plain words whether your
laptop can reach it - and what to change if not.

Run:  pythonw linkscope.pyw      (or double-click)
Needs: Python 3 with tkinter, Wireshark/tshark + Npcap installed.
"""
import ipaddress
import json
import os
import subprocess
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
NOWIN = 0x08000000  # CREATE_NO_WINDOW
SKIP_DESC = ("hyper-v", "tailscale", "wireguard", "tap-", "virtual", "bluetooth",
             "loopback", "vpn", "wan miniport")
FIELDS = ["frame.time_epoch", "eth.src", "eth.src_resolved", "eth.dst", "vlan.id",
          "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "ip.src", "ip.dst",
          "ipv6.src", "_ws.col.protocol", "dhcp.option.dhcp", "dhcp.option.hostname",
          "lldp.tlv.system.name", "cdp.deviceid"]

PS_ADAPTERS = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$a=@(Get-NetAdapter | Select Name,InterfaceDescription,@{n='Status';e={"$($_.Status)"}},LinkSpeed,MacAddress,ifIndex,InterfaceGuid,Virtual)
$ip=@(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Select InterfaceIndex,IPAddress,PrefixLength,@{n='Origin';e={"$($_.PrefixOrigin)"}})
$gw=@(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -EA SilentlyContinue | Select InterfaceIndex,NextHop,RouteMetric)
$st=@(Get-NetAdapterStatistics -EA SilentlyContinue | Select Name,ReceivedUnicastPackets,ReceivedBroadcastPackets,ReceivedMulticastPackets,SentUnicastPackets)
@{a=$a;ip=$ip;gw=$gw;st=$st} | ConvertTo-Json -Depth 3 -Compress
"""


def run_ps(script, timeout=30):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, creationflags=NOWIN, timeout=timeout)
    return r.returncode, r.stdout.decode("utf-8", "replace").lstrip("\ufeff"), \
        r.stderr.decode("utf-8", "replace")


def ago(t):
    s = int(time.time() - t)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    return f"{s // 3600}h ago"


def is_apipa(ip):
    return ipaddress.ip_address(ip) in ipaddress.ip_network("169.254.0.0/16")


# --------------------------------------------------------------------------- model
class Adapter:
    def __init__(self, d, ips, gws, stats):
        self.name = d["Name"]
        self.desc = d.get("InterfaceDescription") or ""
        self.status = d.get("Status") or ""
        self.speed = d.get("LinkSpeed") or ""
        self.mac = (d.get("MacAddress") or "").replace("-", ":").lower()
        self.ifindex = d["ifIndex"]
        self.guid = d.get("InterfaceGuid") or ""
        self.virtual = bool(d.get("Virtual"))
        self.ifaces = [ipaddress.ip_interface(f"{i['IPAddress']}/{i['PrefixLength']}")
                       for i in ips if i["InterfaceIndex"] == self.ifindex]
        self.origins = {i["IPAddress"]: i.get("Origin", "")
                        for i in ips if i["InterfaceIndex"] == self.ifindex}
        self.gws = [g["NextHop"] for g in gws if g["InterfaceIndex"] == self.ifindex]
        self.stats = stats.get(self.name, {})

    @property
    def up(self):
        return self.status == "Up"

    @property
    def wifi(self):
        dl = self.desc.lower()
        return "wi-fi" in dl or "wireless" in dl or "wlan" in dl

    @property
    def wired_physical(self):
        dl = self.desc.lower()
        return not self.virtual and not any(s in dl for s in SKIP_DESC)

    def capturable(self, include_wifi):
        return self.up and self.wired_physical and (include_wifi or not self.wifi)

    @property
    def real_ifaces(self):
        """Usable IPv4 interfaces: no 169.254 self-assigned, no /32 host-only."""
        return [i for i in self.ifaces if not is_apipa(str(i.ip)) and i.network.prefixlen < 32]

    def ipv4_text(self):
        return ", ".join(f"{i.ip}/{i.network.prefixlen}" +
                         (" (self-assigned)" if is_apipa(str(i.ip)) else "")
                         for i in self.ifaces) or "-"


class Neighbor:
    def __init__(self, guid, mac, vendor):
        self.guid, self.mac, self.vendor = guid, mac, vendor
        self.first = self.last = time.time()
        self.pkts = 0
        self.to_me = 0
        self.claimed = {}       # ipv4 -> last seen   (from ARP: authoritative)
        self.ipsrc = {}         # ipv4 -> last seen   (from IP source: may be forwarded)
        self.wants = {}         # ipv4 -> count       (ARP who-has it sent)
        self.v6 = set()
        self.protos = set()
        self.vlans = set()
        self.names = set()
        self.dhcp_ask = False

    def ipv4s(self):
        if self.claimed:
            return sorted(self.claimed, key=ipaddress.ip_address)
        recent = sorted(self.ipsrc, key=lambda k: -self.ipsrc[k])[:3]
        return sorted(recent, key=ipaddress.ip_address)


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.neigh = {}         # (guid, mac) -> Neighbor
        self.my_asks = {}       # guid -> {ip: [count, last]}
        self.answered = {}      # guid -> {ip: mac}

    def clear(self):
        with self.lock:
            self.neigh.clear()
            self.my_asks.clear()
            self.answered.clear()

    def ingest(self, guid, mymac, f):
        if len(f) < len(FIELDS):
            return
        (_t, src, res, dst, vlan, op, asrc, adst, isrc, _idst, v6, proto,
         dhcp, host, lldp, cdp) = f[:16]
        src, dst, now = src.lower(), dst.lower(), time.time()
        if not src:
            return
        with self.lock:
            if op == "2" and asrc:          # someone (maybe us) answered for asrc
                self.answered.setdefault(guid, {})[asrc] = src
                for nb in self.neigh.values():
                    if nb.guid == guid:
                        nb.wants.pop(asrc, None)
            if src == mymac:
                if op == "1" and adst:
                    d = self.my_asks.setdefault(guid, {}).setdefault(adst, [0, 0])
                    d[0] += 1
                    d[1] = now
                return
            n = self.neigh.get((guid, src))
            if n is None:
                vendor = res.split("_")[0] if res and res.lower() != src and "_" in res else ""
                n = self.neigh[(guid, src)] = Neighbor(guid, src, vendor)
            n.last = now
            n.pkts += 1
            if dst == mymac:
                n.to_me += 1
            if proto and len(n.protos) < 30:
                n.protos.add(proto)
            if vlan:
                n.vlans.update(v for v in vlan.split(",") if v)
            if op and asrc and asrc != "0.0.0.0":
                n.claimed[asrc] = now
            if op == "1" and adst and adst != asrc and adst not in self.answered.get(guid, {}):
                n.wants[adst] = n.wants.get(adst, 0) + 1
            if isrc:
                if isrc == "0.0.0.0":
                    if dhcp in ("1", "3"):
                        n.dhcp_ask = True
                else:
                    a = ipaddress.ip_address(isrc)
                    if not (a.is_multicast or a.is_unspecified) and len(n.ipsrc) < 200:
                        n.ipsrc[isrc] = now
            if v6.lower().startswith("fe80"):
                n.v6.add(v6.lower())
            for nm in (host, lldp, cdp):
                if nm:
                    n.names.add(nm)

    def snapshot(self):
        with self.lock:
            return list(self.neigh.values()), \
                {g: dict(v) for g, v in self.my_asks.items()}, \
                {g: dict(v) for g, v in self.answered.items()}


class Capture(threading.Thread):
    def __init__(self, adapter, store):
        super().__init__(daemon=True)
        self.guid, self.mymac, self.name, self.store = adapter.guid, adapter.mac, adapter.name, store
        self.proc = None
        self.error = None
        self.running = True

    def run(self):
        cmd = [TSHARK, "-i", rf"\Device\NPF_{self.guid}", "-l", "-N", "m", "-s", "256",
               "-M", "20000", "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
        for fld in FIELDS:
            cmd += ["-e", fld]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.DEVNULL, creationflags=NOWIN,
                                         text=True, encoding="utf-8", errors="replace", bufsize=1)
            threading.Thread(target=self._drain_err, daemon=True).start()
            for line in self.proc.stdout:
                self.store.ingest(self.guid, self.mymac, line.rstrip("\r\n").split("|"))
        except Exception as e:  # noqa: BLE001
            self.error = str(e)
        self.running = False

    def _drain_err(self):
        for line in self.proc.stderr:
            if "Capturing on" not in line and "packets captured" not in line and line.strip():
                self.error = line.strip()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


# ------------------------------------------------------------------------ analysis
def owners_of(adapters, ip):
    """Up adapters whose (real) subnet contains ip, best (longest prefix) first."""
    a = ipaddress.ip_address(ip)
    hits = [(ad, i) for ad in adapters if ad.up for i in ad.real_ifaces if a in i.network]
    return sorted(hits, key=lambda h: -h[1].network.prefixlen)


def all_claims(neighbors):
    out = {}
    for n in neighbors:
        for ip in n.ipv4s():
            out.setdefault(ip, []).append(n)
    return out


def suggest_ip(n, neighbors, adapters):
    ips = n.ipv4s()
    if not ips:
        return None
    dev = ipaddress.ip_address(ips[0])
    net = ipaddress.ip_network(f"{dev}/24", strict=False)
    taken = set(all_claims(neighbors)) | {str(i.ip) for ad in adapters for i in ad.ifaces}

    def ok(c):
        return c in net and str(c) not in taken and c != dev and \
            c not in (net.network_address, net.broadcast_address)
    for cand in sorted(n.wants, key=lambda k: -n.wants[k]):
        c = ipaddress.ip_address(cand)
        if ok(c):
            return str(c), 24, "the device is already asking for this address, so it is " \
                               "probably the one it expects to talk to"
    for last in list(range(200, 250)) + list(range(2, 200)):
        c = net.network_address + last
        if ok(c):
            return str(c), 24, "an address in the device's range that nobody seems to use"
    return None


def analyze(n, adapters, neighbors):
    """-> (short verdict, tag, explanation lines, suggestion or None)"""
    A = next((a for a in adapters if a.guid == n.guid), None)
    aname = A.name if A else "?"
    lines, tag, short, sugg = [], "ok", "", None
    rank = {"idle": 0, "ok": 1, "warn": 2, "bad": 3}

    def bump(t, s):
        nonlocal tag, short
        if rank[t] > rank[tag] or not short:
            tag, short = t, s

    ips = n.ipv4s()
    from_arp = bool(n.claimed)
    if not ips:
        if n.dhcp_ask:
            bump("warn", "asking for DHCP")
            lines.append("It is sending DHCP requests (\"can someone give me an IP?\") and "
                         "nothing on this cable answers. It has no IPv4 address yet.")
            lines.append("Fix: give it a static IP in its own config, or run a DHCP server "
                         "on this adapter.")
        elif n.v6:
            bump("warn", "IPv6 link-local only")
            ll = sorted(n.v6)[0]
            lines.append("No IPv4 address heard yet, but it has an IPv6 link-local address. "
                         "That works without any subnet setup:")
            lines.append(f"    ping {ll}%{A.ifindex if A else '?'}")
        else:
            bump("idle", "no IP heard yet")
            lines.append(f"Heard only non-IP traffic so far ({', '.join(sorted(n.protos)) or '-'}).")
            lines.append("Wait a bit, or power-cycle the device: almost everything sends "
                         "ARP/DHCP while it boots.")
        return short, tag, lines, None

    src_note = "" if from_arp else \
        " (seen as IP source only, not in ARP; if this device is a router these may be " \
        "addresses it forwards for)"
    lines.append(f"Uses IPv4: {', '.join(ips)}{src_note}")
    mine = [str(i.ip) for i in A.ifaces] if A else []
    for ip in ips:
        here = [i for i in (A.real_ifaces if A else []) if ipaddress.ip_address(ip) in i.network]
        owners = owners_of(adapters, ip)
        if ip in mine:
            bump("bad", "SAME IP AS YOU")
            lines.append(f"✖ {ip} is the same address your laptop uses on {aname}. Two devices "
                         f"with one IP: change one of them.")
        elif here:
            best = owners[0][0] if owners else A
            if best is A:
                bump("ok", "reachable")
                lines.append(f"✔ {ip} is inside {here[0].with_prefixlen} on {aname}, so "
                             f"Windows can talk to it directly on this cable.")
            else:
                bump("bad", f"routed to {best.name}")
                lines.append(f"✖ {ip} fits {aname}'s subnet, but {best.name} has a more specific "
                             f"subnet ({owners[0][1].with_prefixlen}) for it, so Windows sends "
                             f"packets out {best.name} instead.")
            dup = [o for o in owners if o[0] is not A]
            if dup and best is A:
                bump("warn", "subnet on 2 adapters")
                lines.append(f"⚠ {dup[0][0].name} is ALSO on {dup[0][1].network}. Windows picks "
                             f"one adapter for that range (lowest metric), so traffic may leave "
                             f"through the wrong cable.")
        elif owners:
            B, bi = owners[0]
            bump("bad", f"routed to {B.name}")
            lines.append(f"✖ {ip} is in {bi.network}, which is configured on {B.name}, not on "
                         f"{aname}. Windows sends packets for {ip} out {B.name}, so this "
                         f"device never sees them.")
        else:
            bump("bad", "wrong subnet")
            yours = A.ipv4_text() if A else "-"
            lines.append(f"✖ {ip} is not in any subnet your laptop has on {aname} "
                         f"(you are {yours}). Windows sends {ip} to your default gateway "
                         f"(Wi-Fi/VPN) instead, so the device never sees your packets, and its "
                         f"replies to you would be dropped too.")

    claims = all_claims(neighbors)
    for ip in ips:
        others = [o for o in claims.get(ip, []) if o is not n]
        for o in others:
            where = next((a.name for a in adapters if a.guid == o.guid), "?")
            bump("warn", "IP used twice")
            lines.append(f"⚠ {ip} is also used by {o.vendor or 'device'} {o.mac} on {where}. "
                         f"If those two cables ever end up on the same network, they will clash.")

    if n.wants:
        top = sorted(n.wants, key=lambda k: -n.wants[k])[:6]
        lines.append(f"It keeps asking \"who has …?\" for: {', '.join(top)}. Nobody answers, "
                     f"so those hosts are not on this cable. These are usually the IPs it "
                     f"expects (its PC/GCS, gateway, peers).")
        if A and ips:
            offnet = [w for w in top if not any(ipaddress.ip_address(w) in
                      ipaddress.ip_network(f"{ip}/24", strict=False) for ip in ips)]
            if offnet:
                lines.append(f"  {', '.join(offnet)} lie outside its own /24, so it probably "
                             f"uses a wider mask or is looking for a gateway.")
    if n.vlans:
        lines.append(f"⚠ Its traffic is VLAN-tagged ({', '.join(sorted(n.vlans))}). Windows "
                     f"ignores tagged frames unless the adapter is set to that VLAN.")
    if n.names:
        lines.append(f"Name(s) announced: {', '.join(sorted(n.names))}")
    if n.v6:
        lines.append(f"IPv6 link-local (works without any IPv4 setup): "
                     f"ping {sorted(n.v6)[0]}%{A.ifindex if A else '?'}")

    if tag == "bad" and A:
        sugg = suggest_ip(n, neighbors, adapters)
        if sugg:
            ip_s, pfx, why = sugg
            lines.append("")
            lines.append(f"Suggested fix: add {ip_s}/{pfx} to {aname} ({why}).")
            net = ipaddress.ip_network(f"{ip_s}/{pfx}", strict=False)
            clash = [a.name for a in adapters if a is not A and a.up and
                     any(i.network.overlaps(net) for i in a.real_ifaces)]
            if clash:
                lines.append(f"  ⚠ but {', '.join(clash)} already uses that range. Unplug or "
                             f"disable it first, or Windows may still send traffic there.")
    return short, tag, lines, (sugg[0], sugg[1], A.name) if sugg and A else None


def adapter_notes(A, adapters, neighbors, my_asks, answered):
    notes, lines = [], []
    if A.status == "Disconnected":
        notes.append("cable unplugged / no link")
    elif not A.up:
        notes.append(A.status.lower())
    if A.up and not A.real_ifaces and A.wired_physical:
        notes.append("no usable IPv4")
        lines.append("✖ Up, but no usable IPv4 address (only none or 169.254 self-assigned). "
                     "With DHCP and no DHCP server on the cable, Windows invents a 169.254 "
                     "address.")
    for i in A.real_ifaces:
        for B in adapters:
            if B is A or not B.up:
                continue
            for j in B.real_ifaces:
                if i.network.overlaps(j.network):
                    notes.append(f"overlaps {B.name}")
                    lines.append(f"⚠ {i.with_prefixlen} overlaps {B.name}'s {j.with_prefixlen}. "
                                 f"Windows will send that range out only one of them.")
    rb = A.stats.get("ReceivedBroadcastPackets") or 0
    ru = A.stats.get("ReceivedUnicastPackets") or 0
    if A.up and A.wired_physical:
        if rb == 0 and ru == 0 and not A.stats.get("ReceivedMulticastPackets"):
            notes.append("nothing received")
            lines.append("Link is up but nothing has been received at all. The device may be "
                         "off, booting, or silent until spoken to.")
        elif ru == 0 and rb > 0:
            notes.append("hears broadcasts, no replies")
            lines.append("Receives broadcasts but has never received a single packet addressed "
                         "to this laptop. Something is on the cable but has never answered you, "
                         "usually because it is on a different subnet. See Devices below.")
    nb = [n for n in neighbors if n.guid == A.guid]
    if nb:
        lines.append(f"{len(nb)} device(s) heard on this cable since capture started.")
    asks = my_asks.get(A.guid, {})
    ans = answered.get(A.guid, {})
    unanswered = [(ip, c) for ip, (c, _t) in asks.items() if ip not in ans]
    if unanswered:
        lines.append("")
        lines.append("Your laptop asked \"who has …?\" on this cable with NO answer:")
        for ip, c in sorted(unanswered, key=lambda x: -x[1])[:10]:
            claim = [n for n in neighbors if ip in n.claimed]
            extra = ""
            if claim:
                where = next((a.name for a in adapters if a.guid == claim[0].guid), "?")
                extra = f"  (but {claim[0].mac} on {where} claims it)"
            lines.append(f"    {ip}  ×{c}{extra}")
        lines.append("Nobody on this cable owns those addresses.")
    return notes, lines


# ----------------------------------------------------------------------------- GUI
class App:
    def __init__(self, root):
        self.root = root
        self.store = Store()
        self.adapters = []
        self.captures = {}
        self.include_wifi = tk.BooleanVar(value=False)
        self.suggestion = None
        self.detail_key = None
        self.busy = False

        root.title("LinkScope")
        root.geometry("1280x820")
        root.minsize(900, 600)
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=22)

        top = ttk.Frame(root, padding=(8, 6))
        top.pack(fill="x")
        ttk.Button(top, text="Refresh", command=self.refresh_adapters).pack(side="left")
        ttk.Checkbutton(top, text="Also listen on Wi-Fi", variable=self.include_wifi,
                        command=self.refresh_adapters).pack(side="left", padx=10)
        ttk.Button(top, text="Clear heard devices", command=self.clear).pack(side="left")
        self.status = ttk.Label(top, text="Starting…", foreground="#555")
        self.status.pack(side="left", padx=14)

        pw = ttk.PanedWindow(root, orient="vertical")
        pw.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # adapters
        fa = ttk.LabelFrame(pw, text=" Adapters  (your side of each cable) ", padding=4)
        cols = ("name", "status", "speed", "mac", "ipv4", "gw", "rx", "notes")
        self.at = ttk.Treeview(fa, columns=cols, show="headings", height=7, selectmode="browse")
        for c, h, w in zip(cols, ("Adapter", "Link", "Speed", "MAC", "IPv4 address / prefix",
                                  "Gateway", "Rx bcast / unicast", "Notes"),
                           (170, 90, 80, 130, 290, 110, 120, 300)):
            self.at.heading(c, text=h)
            self.at.column(c, width=w, stretch=c in ("ipv4", "notes"))
        self.at.tag_configure("down", foreground="#999")
        self.at.tag_configure("warn", foreground="#a35b00")
        self.at.tag_configure("bad", foreground="#b00020")
        self.at.pack(side="left", fill="both", expand=True)
        ab = ttk.Frame(fa)
        ab.pack(side="left", fill="y", padx=(6, 0))
        ttk.Button(ab, text="Add IP…", command=self.add_ip_dialog).pack(fill="x")
        ttk.Button(ab, text="Remove IP…", command=self.remove_ip_dialog).pack(fill="x", pady=4)
        self.at.bind("<<TreeviewSelect>>", lambda e: self.show_adapter())
        pw.add(fa, weight=2)

        # neighbors
        fn = ttk.LabelFrame(pw, text=" Devices heard on the cables  (their side, passive "
                                     "capture - works across subnets) ", padding=4)
        cols = ("adapter", "mac", "vendor", "ips", "wants", "pkts", "last", "verdict")
        self.nt = ttk.Treeview(fn, columns=cols, show="headings", height=8, selectmode="browse")
        for c, h, w in zip(cols, ("On adapter", "MAC", "Vendor", "Its IPv4", "Looking for",
                                  "Pkts", "Last heard", "Verdict"),
                           (120, 130, 110, 200, 220, 60, 80, 200)):
            self.nt.heading(c, text=h)
            self.nt.column(c, width=w, stretch=c in ("ips", "wants", "verdict"))
        for t, col in (("ok", "#1b7a1b"), ("warn", "#a35b00"), ("bad", "#b00020"),
                       ("idle", "#777")):
            self.nt.tag_configure(t, foreground=col)
        sb = ttk.Scrollbar(fn, orient="vertical", command=self.nt.yview)
        self.nt.configure(yscrollcommand=sb.set)
        self.nt.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.nt.bind("<<TreeviewSelect>>", lambda e: self.show_neighbor())
        self.nt.bind("<Double-1>", self.neighbor_to_ping)
        pw.add(fn, weight=3)

        # details + ping
        fd = ttk.LabelFrame(pw, text=" Explanation ", padding=4)
        bar = ttk.Frame(fd)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Label(bar, text="Why can't I reach:").pack(side="left")
        self.target = ttk.Entry(bar, width=22)
        self.target.pack(side="left", padx=4)
        self.target.bind("<Return>", lambda e: self.diagnose())
        self.diag_btn = ttk.Button(bar, text="Ping + explain", command=self.diagnose)
        self.diag_btn.pack(side="left")
        self.fix_btn = ttk.Button(bar, text="Apply suggested fix", command=self.apply_fix,
                                  state="disabled")
        self.fix_btn.pack(side="right")
        self.text = tk.Text(fd, height=12, wrap="word", font=("Consolas", 10), relief="flat",
                            background="#fbfbfb", padx=8, pady=6)
        self.text.pack(fill="both", expand=True)
        self.text.tag_configure("h", font=("Segoe UI Semibold", 11))
        pw.add(fd, weight=3)
        self.write("LinkScope", ["Select an adapter or a device for an explanation, or type an "
                                 "IP above and press Enter.",
                                 "",
                                 "How it works: ping uses IP, which only works when both ends "
                                 "are in the same subnet. Underneath, Ethernet delivers "
                                 "broadcast frames (like ARP \"who has 1.2.3.4?\") to everything "
                                 "on the cable whatever its IP. LinkScope listens to those, so "
                                 "it can see a device and its real address even when ping "
                                 "can't."])

        root.protocol("WM_DELETE_WINDOW", self.quit)
        if not os.path.exists(TSHARK):
            messagebox.showwarning("LinkScope", f"tshark not found at\n{TSHARK}\n\nInstall "
                                   "Wireshark (with Npcap). Adapter info still works.")
        self.refresh_adapters()
        self.root.after(1000, self.tick)
        self.root.after(5000, self.auto_refresh)

    # ---------------------------------------------------------------- plumbing
    def write(self, title, lines):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", title + "\n", "h")
        self.text.insert("end", "\n".join(lines))
        self.text.configure(state="disabled")

    def quit(self):
        for c in self.captures.values():
            c.stop()
        self.root.destroy()

    def clear(self):
        self.store.clear()
        for i in self.nt.get_children():
            self.nt.delete(i)

    def auto_refresh(self):
        self.refresh_adapters()
        self.root.after(5000, self.auto_refresh)

    def refresh_adapters(self):
        if self.busy:
            return
        self.busy = True

        def work():
            try:
                rc, out, err = run_ps(PS_ADAPTERS)
                data = json.loads(out)
                stats = {s["Name"]: s for s in data.get("st") or []}
                ads = [Adapter(d, data.get("ip") or [], data.get("gw") or [], stats)
                       for d in data.get("a") or []]
                ads.sort(key=lambda a: (not a.up, not a.wired_physical, a.name))
                self.root.after(0, self.adapters_loaded, ads)
            except Exception as e:  # noqa: BLE001
                self.root.after(0, lambda: self.status.configure(text=f"Adapter query failed: {e}"))
            finally:
                self.busy = False
        threading.Thread(target=work, daemon=True).start()

    def adapters_loaded(self, ads):
        self.adapters = ads
        want = {a.guid: a for a in ads if a.capturable(self.include_wifi.get())}
        for g in list(self.captures):
            c = self.captures[g]
            if g not in want or not c.running:
                c.stop()
                del self.captures[g]
        if os.path.exists(TSHARK):
            for g, a in want.items():
                if g not in self.captures:
                    c = Capture(a, self.store)
                    self.captures[g] = c
                    c.start()
        self.render_adapters()

    def render_adapters(self):
        neighbors, asks, ans = self.store.snapshot()
        sel = self.at.selection()
        seen = set()
        for A in self.adapters:
            notes, _ = adapter_notes(A, self.adapters, neighbors, asks, ans)
            cap = self.captures.get(A.guid)
            if cap:
                notes.insert(0, "listening" if cap.running and not cap.error else
                             f"capture error: {cap.error}")
            rx = f"{A.stats.get('ReceivedBroadcastPackets', '-')} / " \
                 f"{A.stats.get('ReceivedUnicastPackets', '-')}"
            vals = (A.name, A.status, A.speed if A.up else "", A.mac, A.ipv4_text(),
                    ", ".join(A.gws) or "", rx, "; ".join(notes))
            tag = "down" if not A.up else \
                "bad" if any(n.startswith(("no usable", "hears broad", "capture err"))
                             for n in notes) else \
                "warn" if any(n.startswith(("overlaps", "nothing")) for n in notes) else ""
            iid = A.guid or A.name
            seen.add(iid)
            if self.at.exists(iid):
                self.at.item(iid, values=vals, tags=(tag,))
            else:
                self.at.insert("", "end", iid=iid, values=vals, tags=(tag,))
        for iid in self.at.get_children():
            if iid not in seen:
                self.at.delete(iid)
        for i, A in enumerate(self.adapters):
            iid = A.guid or A.name
            if self.at.exists(iid):
                self.at.move(iid, "", i)
        if sel and self.at.exists(sel[0]):
            self.at.selection_set(sel)
        on = [c.name for c in self.captures.values() if c.running]
        self.status.configure(text=("Listening on: " + ", ".join(on)) if on else
                              "Not listening on any cable (no wired adapter is up)")

    def tick(self):
        try:
            self.render_neighbors()
            self.render_adapters_light()
            if self.detail_key and self.detail_key[0] == "n":
                self.show_neighbor(refresh=True)
        finally:
            self.root.after(1000, self.tick)

    def render_adapters_light(self):
        pass  # adapter rows are refreshed with the 5 s adapter poll

    def render_neighbors(self):
        neighbors, _, _ = self.store.snapshot()
        names = {a.guid: a.name for a in self.adapters}
        for n in sorted(neighbors, key=lambda n: (names.get(n.guid, ""), n.first)):
            short, tag, _, _ = analyze(n, self.adapters, neighbors)
            wants = ", ".join(sorted(n.wants, key=lambda k: -n.wants[k])[:4])
            vals = (names.get(n.guid, "?"), n.mac, n.vendor, ", ".join(n.ipv4s()) or
                    ("(asking DHCP)" if n.dhcp_ask else "-"), wants, n.pkts, ago(n.last), short)
            iid = f"{n.guid}|{n.mac}"
            if self.nt.exists(iid):
                self.nt.item(iid, values=vals, tags=(tag,))
            else:
                self.nt.insert("", "end", iid=iid, values=vals, tags=(tag,))

    # ---------------------------------------------------------------- details
    def find_neighbor(self, iid):
        neighbors, _, _ = self.store.snapshot()
        g, m = iid.split("|", 1)
        return next((n for n in neighbors if n.guid == g and n.mac == m), None), neighbors

    def show_neighbor(self, refresh=False):
        sel = self.nt.selection()
        if not sel:
            return
        if not refresh:
            self.at.selection_remove(self.at.selection())
        n, neighbors = self.find_neighbor(sel[0])
        if not n:
            return
        self.detail_key = ("n", sel[0])
        short, tag, lines, sugg = analyze(n, self.adapters, neighbors)
        head = [f"MAC {n.mac}   vendor: {n.vendor or 'unknown'}   packets: {n.pkts}   "
                f"to you: {n.to_me}   first heard {ago(n.first)}",
                f"Protocols: {', '.join(sorted(n.protos)) or '-'}", ""]
        if refresh and self.text.get("1.0", "end").count("\n") and \
                getattr(self, "_last_detail", None) == (head[1:], lines):
            return
        self._last_detail = (head[1:], lines)
        self.write(f"{n.vendor or 'Device'} {n.mac}  -  {short}", head + lines)
        self.set_suggestion(sugg)

    def show_adapter(self):
        sel = self.at.selection()
        if not sel:
            return
        self.nt.selection_remove(self.nt.selection())
        A = next((a for a in self.adapters if (a.guid or a.name) == sel[0]), None)
        if not A:
            return
        self.detail_key = ("a", sel[0])
        neighbors, asks, ans = self.store.snapshot()
        notes, lines = adapter_notes(A, self.adapters, neighbors, asks, ans)
        head = [f"{A.desc}", f"Status {A.status}   speed {A.speed}   MAC {A.mac}   "
                f"ifIndex {A.ifindex}"]
        for i in A.ifaces:
            head.append(f"  {i.with_prefixlen:<20} = reaches {i.network[0]} … "
                        f"{i.network[-1]}   ({self.origin(A, i)})")
        if A.gws:
            head.append(f"  default gateway: {', '.join(A.gws)}")
        self.write(A.name, head + [""] + (lines or ["Nothing unusual."]))
        self.set_suggestion(None)

    @staticmethod
    def origin(A, i):
        o = A.origins.get(str(i.ip), "")
        return {"Manual": "static", "Dhcp": "from DHCP", "WellKnown": "self-assigned"}.get(o, o)

    def set_suggestion(self, sugg):
        self.suggestion = sugg
        if sugg:
            self.fix_btn.configure(state="normal",
                                   text=f"Add {sugg[0]}/{sugg[1]} to {sugg[2]}")
        else:
            self.fix_btn.configure(state="disabled", text="Apply suggested fix")

    def neighbor_to_ping(self, _e):
        sel = self.nt.selection()
        if sel:
            n, _ = self.find_neighbor(sel[0])
            if n and n.ipv4s():
                self.target.delete(0, "end")
                self.target.insert(0, n.ipv4s()[0])
                self.diagnose()

    # ---------------------------------------------------------------- diagnose
    def diagnose(self):
        t = self.target.get().strip()
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            self.write("Not an IP address", [f"'{t}' is not a valid IP address."])
            return
        if ip.version != 4:
            self.write("IPv4 only", ["The explain feature handles IPv4 addresses. For IPv6 "
                                     "link-local, use: ping fe80::…%ifIndex"])
            return
        self.detail_key = None
        self.set_suggestion(None)
        self.diag_btn.configure(state="disabled")
        self.write(f"Diagnosing {ip} …", ["Pinging and checking ARP…"])
        adapters = list(self.adapters)

        def work():
            r = subprocess.run(["ping", "-n", "2", "-w", "1000", str(ip)], capture_output=True,
                               creationflags=NOWIN)
            out = r.stdout.decode("mbcs", "replace")
            replies = out.count("TTL=") + out.count("ttl=")
            rc, nb, _ = run_ps("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
                               f"@(Get-NetNeighbor -IPAddress {ip} -EA SilentlyContinue | "
                               "Select InterfaceAlias,LinkLayerAddress,"
                               "@{n='State';e={\"$($_.State)\"}}) | ConvertTo-Json -Compress")
            try:
                arp = json.loads(nb) if nb.strip() else []
                arp = arp if isinstance(arp, list) else [arp]
            except json.JSONDecodeError:
                arp = []
            self.root.after(0, self.diagnose_done, ip, adapters, replies, out, arp)
        threading.Thread(target=work, daemon=True).start()

    def diagnose_done(self, ip, adapters, replies, out, arp):
        self.diag_btn.configure(state="normal")
        neighbors, asks, _ = self.store.snapshot()
        s = str(ip)
        L = []
        owners = owners_of(adapters, s)
        claimers = [n for n in neighbors if s in n.ipv4s()]
        names = {a.guid: a for a in adapters}
        sugg = None

        L.append("1. Where does Windows send it?")
        if owners:
            A, i = owners[0]
            L.append(f"   {s} is inside {i.with_prefixlen} on {A.name}, so Windows treats it as "
                     f"local and sends it straight out that cable.")
            if len(owners) > 1:
                L.append(f"   ⚠ {', '.join(o[0].name for o in owners[1:])} also cover this "
                         f"range. Only one adapter is used, and it may be the wrong cable.")
        else:
            A = None
            gw = next((a for a in adapters if a.up and a.gws), None)
            L.append(f"   {s} is not in any subnet on your adapters, so Windows sends it to the "
                     f"default gateway{' via ' + gw.name if gw else ''}. A device on an Ethernet "
                     f"cable will never see that ping.")

        L.append("")
        L.append("2. Did anything answer \"who has " + s + "?\" (ARP)?")
        resolved = [a for a in arp if a.get("State") in ("Reachable", "Stale", "Delay", "Probe",
                                                         "Permanent")
                    and a.get("LinkLayerAddress") not in ("", "00-00-00-00-00-00")]
        if resolved:
            a = resolved[0]
            L.append(f"   Yes. {a['InterfaceAlias']} learned MAC {a['LinkLayerAddress']} "
                     f"({a['State']}). The device is there at that IP.")
        elif A:
            st = arp[0].get("State") if arp else "no entry"
            L.append(f"   No (state: {st}). Nothing on {A.name}'s cable claims {s}.")
        else:
            L.append("   Not asked. Windows doesn't send ARP for addresses outside its subnets.")

        L.append("")
        L.append(f"3. Ping: {replies} of 2 replies.")
        L.append("")
        if replies:
            title = f"{s} answers ✔"
            L.append("Conclusion: it works.")
            mac = (resolved[0]["LinkLayerAddress"].replace("-", ":").lower()
                   if resolved else "")
            twins = [n for n in claimers if n.mac != mac]
            for n in twins:
                B = names.get(n.guid)
                L.append(f"⚠ But {n.vendor or 'another device'} {n.mac} on "
                         f"{B.name if B else '?'} also uses {s}. The reply came from "
                         f"{mac or 'the device'}, so make sure that's the one you meant.")
        elif resolved:
            title = f"{s} is there but ignores ping"
            L.append("Conclusion: the device answered ARP, so it is on the cable with that IP, "
                     "but it didn't answer ping. Usual causes:")
            L.append("  • its firewall blocks ICMP (try the real service instead: ssh, http, "
                     "mavlink…)")
            L.append("  • its subnet mask doesn't cover YOUR address, so it sends the reply to its "
                     "gateway. Check whether it keeps asking for a gateway IP (Looking for).")
            for n in claimers:
                if n.wants:
                    L.append(f"    It is looking for: {', '.join(list(n.wants)[:5])}")
        else:
            title = f"Can't reach {s}"
            if claimers:
                L.append(f"Good news: I have heard a device using {s}:")
                for n in claimers:
                    B = names.get(n.guid)
                    L.append(f"  • {n.vendor or 'device'} {n.mac} on {B.name if B else '?'}")
                    _, _, lines, sg = analyze(n, adapters, neighbors)
                    L += ["      " + x for x in lines if x.startswith(("✖", "⚠", "Suggested"))]
                    sugg = sugg or sg
            elif A:
                here = [n for n in neighbors if n.guid == A.guid]
                if here:
                    L.append(f"No device on {A.name}'s cable uses {s}. What IS on that cable:")
                    for n in here:
                        L.append(f"  • {n.vendor or 'device'} {n.mac} → "
                                 f"{', '.join(n.ipv4s()) or 'no IPv4 heard'}"
                                 f"{'   (looking for ' + ', '.join(list(n.wants)[:3]) + ')' if n.wants else ''}")
                    L.append("Did you mean one of those? Select it in the list for a fix.")
                    if len(here) == 1:
                        sugg = analyze(here[0], adapters, neighbors)[3]
                else:
                    cap = self.captures.get(A.guid)
                    L.append(f"Nothing at all has been heard on {A.name}'s cable"
                             f"{'' if cap else ' (not listening on it)'}. The device is off, "
                             f"still booting, on another cable, or silent until spoken to. "
                             f"Try power-cycling it while LinkScope is listening.")
            else:
                L.append("I haven't heard any device using that IP on any cable. If it is a "
                         "wired device, check which adapter it's on and add an IP in its range "
                         "there.")
        self.write(title, L + ["", "─ raw ping ─", out.strip()])
        self.set_suggestion(sugg)

    # ---------------------------------------------------------------- IP changes
    def elevated_netsh(self, args, done_msg):
        esc = args.replace("'", "''")
        script = (f"try {{ $p=Start-Process netsh -ArgumentList '{esc}' -Verb RunAs -Wait "
                  f"-PassThru -WindowStyle Hidden -EA Stop; exit $p.ExitCode }} "
                  f"catch {{ Write-Error $_; exit 99 }}")

        def work():
            rc, _o, err = run_ps(script, timeout=120)
            def fin():
                if rc == 0:
                    self.write("Done", [done_msg, "", f"netsh {args}"])
                elif rc == 99:
                    self.write("Cancelled", ["The admin prompt was cancelled or failed.",
                                             err.strip()])
                else:
                    self.write("netsh failed", [f"netsh {args}", f"exit code {rc}", "",
                                                "Common cause: the adapter is set to DHCP. Set "
                                                "it to a static IP first (adapter properties → "
                                                "IPv4), then add extra addresses."])
                self.refresh_adapters()
            self.root.after(0, fin)
        threading.Thread(target=work, daemon=True).start()

    def apply_fix(self):
        if self.suggestion:
            ip, pfx, name = self.suggestion
            self.add_ip_dialog(name, ip, pfx)

    def selected_adapter(self):
        sel = self.at.selection()
        if sel:
            return next((a for a in self.adapters if (a.guid or a.name) == sel[0]), None)
        return None

    def add_ip_dialog(self, name=None, ip="", pfx=24):
        A = self.selected_adapter()
        name = name or (A.name if A else "")
        d = tk.Toplevel(self.root)
        d.title("Add IP address")
        d.transient(self.root)
        d.grab_set()
        f = ttk.Frame(d, padding=12)
        f.pack(fill="both")
        choices = [a.name for a in self.adapters if a.wired_physical or a.wifi]
        ttk.Label(f, text="Adapter").grid(row=0, column=0, sticky="w")
        cb = ttk.Combobox(f, values=choices, state="readonly", width=28)
        cb.set(name if name in choices else (choices[0] if choices else ""))
        cb.grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(f, text="IP address").grid(row=1, column=0, sticky="w")
        e_ip = ttk.Entry(f, width=20)
        e_ip.insert(0, ip)
        e_ip.grid(row=1, column=1, sticky="w", pady=2)
        ttk.Label(f, text="Prefix (/24 = 255.255.255.0)").grid(row=2, column=0, sticky="w")
        e_p = ttk.Entry(f, width=6)
        e_p.insert(0, str(pfx))
        e_p.grid(row=2, column=1, sticky="w", pady=2)
        warn = ttk.Label(f, text="", foreground="#a35b00", wraplength=380)
        warn.grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(f, text="Adds a second address; existing ones are kept. Windows will ask for "
                          "admin permission.", foreground="#555", wraplength=380) \
            .grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 8))

        def check(*_):
            try:
                net = ipaddress.ip_network(f"{e_ip.get().strip()}/{e_p.get().strip()}",
                                           strict=False)
            except ValueError:
                warn.configure(text="")
                return None
            clash = [a.name for a in self.adapters if a.name != cb.get() and a.up and
                     any(i.network.overlaps(net) for i in a.real_ifaces)]
            warn.configure(text=f"⚠ {', '.join(clash)} already uses {net}. Disable/unplug it "
                                f"or Windows may send this range there instead."
                           if clash else f"This adapter will reach {net[0]} … {net[-1]}")
            return net

        for w in (e_ip, e_p):
            w.bind("<KeyRelease>", check)
        cb.bind("<<ComboboxSelected>>", check)
        check()

        def ok():
            net = check()
            try:
                ipaddress.ip_address(e_ip.get().strip())
            except ValueError:
                net = None
            if not net or not cb.get():
                messagebox.showerror("Add IP", "Enter a valid IP and prefix.", parent=d)
                return
            name_q = cb.get().replace('"', "")
            args = (f'interface ipv4 add address name="{name_q}" '
                    f'address={e_ip.get().strip()} mask={net.netmask}')
            d.destroy()
            self.write("Waiting for admin approval…", [f"netsh {args}"])
            self.elevated_netsh(args, f"Added {e_ip.get().strip()}/{net.prefixlen} to "
                                      f"{name_q}. Try pinging the device now.")
        bf = ttk.Frame(f)
        bf.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(bf, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(bf, text="Add", command=ok).pack(side="right", padx=6)
        e_ip.focus_set()

    def remove_ip_dialog(self):
        A = self.selected_adapter()
        if not A:
            messagebox.showinfo("Remove IP", "Select an adapter first.")
            return
        if not A.ifaces:
            messagebox.showinfo("Remove IP", f"{A.name} has no IPv4 addresses.")
            return
        d = tk.Toplevel(self.root)
        d.title(f"Remove IP from {A.name}")
        d.transient(self.root)
        d.grab_set()
        f = ttk.Frame(d, padding=12)
        f.pack(fill="both")
        lb = tk.Listbox(f, height=min(8, len(A.ifaces)), width=32)
        for i in A.ifaces:
            lb.insert("end", f"{i.with_prefixlen}  ({self.origin(A, i)})")
        lb.pack(fill="x")

        def ok():
            s = lb.curselection()
            if not s:
                return
            ip = str(A.ifaces[s[0]].ip)
            if not messagebox.askyesno("Remove IP", f"Remove {ip} from {A.name}?", parent=d):
                return
            d.destroy()
            name_q = A.name.replace('"', "")
            args = f'interface ipv4 delete address name="{name_q}" address={ip}'
            self.write("Waiting for admin approval…", [f"netsh {args}"])
            self.elevated_netsh(args, f"Removed {ip} from {name_q}.")
        bf = ttk.Frame(f)
        bf.pack(fill="x", pady=(8, 0))
        ttk.Button(bf, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(bf, text="Remove", command=ok).pack(side="right", padx=6)


APP_ID = "LinkScope.NetworkDebugger"  # must match install-shortcut.ps1
ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "linkscope.ico")


def main():
    try:
        ctypes = __import__("ctypes")
        # own taskbar identity, so a pinned shortcut and this window share one button
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass
    root = tk.Tk()
    if os.path.exists(ICON):
        try:
            root.iconbitmap(default=ICON)
        except tk.TclError:
            pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
