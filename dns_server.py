# -*- coding: utf-8 -*-
from dnslib import DNSRecord, RR, QTYPE, A, server
import os
import threading

TARGET_IP = "0.0.0.0"  # Your WFC server or other wfc server IP
BLACKLIST_FILE = "blacklist.txt"
WHITELIST_FILE = "whitelist.txt"
CONFIG_FILE = "config.txt"

# Domains to redirect
REDIRECT_DOMAINS = [
    "nintendowifi.net",
    "gamespy.com",
    "nintendo.net",
    "cfh.wapp.wii.com",
    "conntest.nintendowifi.net",
    "wiinat.available.gs.nintendowifi.net",
    "wiinat.natneg1.gs.nintendowifi.net",
    "wiinat.natneg2.gs.nintendowifi.net",
    "wiinat.natneg3.gs.nintendowifi.net",
    "syachi2ds.available.gs.nintendowifi.net",
    "gamestats.gs.nintendowifi.net",
    "gamestats2.gs.nintendowifi.net",
    "gpcm.gs.nintendowifi.net",
    "gpsp.gs.nintendowifi.net",
    "mariokartwii.available.gs.nintendowifi.net",
    "mariokartwii.gamestats.gs.nintendowifi.net",
    "mariokartwii.gamestats2.gs.nintendowifi.net",
    "mariokartwii.master.gs.nintendowifi.net",
    "mariokartwii.ms19.gs.nintendowifi.net",
    "mariokartwii.natneg1.gs.nintendowifi.net",
    "mariokartwii.natneg2.gs.nintendowifi.net",
    "mariokartwii.natneg3.gs.nintendowifi.net",
    "mariokartwii.sake.gs.nintendowifi.net",
    "mariokartwii.race.gs.nintendowifi.net",
    "naswii.nintendowifi.net",
    "nas.nintendowifi.net",
    "smashbrosxwii.available.gs.nintendowifi.net",
    "smashbrosxwii.natneg1.gs.nintendowifi.net",
    "smashbrosxwii.natneg2.gs.nintendowifi.net",
    "smashbrosxwii.natneg3.gs.nintendowifi.net",
    "smashbrosxwii.master.gs.nintendowifi.net",
    "smashbrosxwii.gamestats.gs.nintendowifi.net",
    "smashbrosxwii.gamestats2.gs.nintendowifi.net",
    "smashbrosxwii.ms11.gs.nintendowifi.net",
    "mariokartds.available.gs.nintendowifi.net",
    "mariokartds.master.gs.nintendowifi.net",
    "mariokartds.natneg1.gs.nintendowifi.net",
    "mariokartds.natneg2.gs.nintendowifi.net",
    "mariokartds.ms17.gs.nintendowifi.net",
    "mmvdkds.available.gamespy.com",
    "mmvdkds.master.gs.nintendowifi.net",
    "mmvdkds.sake.gamespy.com",
    "raw2009wii.available.gs.nintendowifi.net",
    "raw2009wii.natneg1.gs.nintendowifi.net",
    "raw2009wii.natneg2.gs.nintendowifi.net",
    "raw2009wii.natneg3.gs.nintendowifi.net",
    "raw2009wii.master.gs.nintendowifi.net",
    "raw2009wii.gamestats.gs.nintendowifi.net",
    "raw2009wii.gamestats2.gs.nintendowifi.net",
    "raw2009wii.ms14.gs.nintendowifi.net",
    "sonic2010wii.available.gs.nintendowifi.net",
    "sonic2010wii.natneg1.gs.nintendowifi.net",
    "sonic2010wii.natneg2.gs.nintendowifi.net",
    "sonic2010wii.natneg3.gs.nintendowifi.net",
    "sonic2010wii.master.gs.nintendowifi.net",
    "sonic2010wii.gamestats.gs.nintendowifi.net",
    "sonic2010wii.gamestats2.gs.nintendowifi.net",
    "sonic2010wii.ms4.gs.nintendowifi.net",
    "sonic2010wii.sake.gs.nintendowifi.net",
    "sonic2010wii.race.gs.nintendowifi.net",
    "pokemondpds.available.gs.nintendowifi.net",
    "pokemondpds.master.gs.nintendowifi.net",
    "unodsi.available.gs.nintendowifi.net",
    "unodsi.master.gs.nintendowifi.net",
    "unodsi.ms2.gs.nintendowifi.net",
    "unowii.available.gs.nintendowifi.net",
    "unowii.natneg1.gs.nintendowifi.net",
    "unowii.natneg2.gs.nintendowifi.net",
    "unowii.natneg3.gs.nintendowifi.net",
    "unowii.master.gs.nintendowifi.net",
    "unowii.gamestats.gs.nintendowifi.net",
    "unowii.gamestats2.gs.nintendowifi.net",
    "unowii.ms11.gs.nintendowifi.net",
    "lozphourds.available.gs.nintendowifi.net",
    "mariosprtwii.available.gs.nintendowifi.net",
    "mariosprtwii.gamestats.gs.nintendowifi.net",
    "mariosprtwii.natneg1.gs.nintendowifi.net",
    "mariosprtwii.natneg2.gs.nintendowifi.net",
    "mariosprtwii.natneg3.gs.nintendowifi.net",
    "mariosprtwii.gamestats2.gs.nintendowifi.net",
    "mariosprtwii.ms10.gs.nintendowifi.net",
    "mariosprtwii.master.gs.nintendowifi.net"
]

# --- File setup ---
for fname, default in [
    (BLACKLIST_FILE, "# Blacklisted IPs\n"),
    (WHITELIST_FILE, "# Whitelisted IPs\n"),
    (CONFIG_FILE, "whitelist_enabled=False\n")
]:
    if not os.path.exists(fname):
        with open(fname, "w") as f:
            f.write(default)

def load_config():
    cfg = {"whitelist_enabled": False}
    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                line = line.strip().lower()
                if line.startswith("whitelist_enabled"):
                    cfg["whitelist_enabled"] = "true" in line or "1" in line
    except Exception:
        pass
    return cfg

def load_list(filename):
    try:
        with open(filename, "r") as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith("#"))
    except Exception:
        return set()

def domain_matches(qname, domain):
    q = qname.rstrip('.').lower()
    d = domain.rstrip('.').lower()
    if q == d:
        return True
    return q.endswith("." + d)

class SimpleNintendoDNS:
    def resolve(self, request, handler):
        config = load_config()
        blacklist = load_list(BLACKLIST_FILE)
        whitelist = load_list(WHITELIST_FILE)

        client_ip = handler.client_address[0]
        qname = str(request.q.qname).lower().rstrip('.')
        reply = request.reply()

        # --- Blacklist check ---
        if client_ip in blacklist:
            print("[DENY] Blocked (blacklist): {}".format(client_ip))
            reply.header.rcode = 3  # NXDOMAIN
            return reply

        # --- Whitelist handling ---
        if config.get("whitelist_enabled") and client_ip not in whitelist:
            # Allow only conntest
            if not domain_matches(qname, "conntest.nintendowifi.net"):
                print("[DENY] Non-whitelisted IP {} -> {}".format(client_ip, qname))
                reply.header.rcode = 3  # NXDOMAIN
                return reply
            else:
                print("[ALLOW] Connection test allowed for {}".format(client_ip))

        # --- Domain redirection (per-client control) ---
        matched = False
        for dom in REDIRECT_DOMAINS:
            if domain_matches(qname, dom):
                matched = True
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(TARGET_IP), ttl=60))
                print("[OK] Redirected {} -> {} (client: {})".format(qname, TARGET_IP, client_ip))
                break

        if not matched:
            print("[PASS] Unhandled domain: {}".format(qname))

        return reply

# --- Main ---
if __name__ == "__main__":
    print("DNS server running on port 53...")
    dns_server = server.DNSServer(AvangardDNSHandler(), port=53, address="0.0.0.0")
    dns_server.start()
