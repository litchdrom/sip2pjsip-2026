import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SECTION_RE = re.compile(r"^\s*(;)?\s*\[([^\]]+)\]\s*$")
KV_RE = re.compile(r"^\s*([^;=\s]+)\s*=\s*(.*?)\s*$")
KV_COMMENTED_RE = re.compile(r"^\s*;\s*([^;=\s]+)\s*=\s*(.*?)\s*$")
REGISTER_RE = re.compile(r"^\s*register\s*=>\s*(.*?)\s*$")


def normalize_bool(v: str) -> Optional[bool]:
    v = v.strip().lower()
    if v in ("yes", "true", "1", "on"):
        return True
    if v in ("no", "false", "0", "off"):
        return False
    return None


@dataclass
class SipGlobals:
    externip: Optional[Tuple[str, int]] = None  # (ip, port)
    localnet: List[str] = field(default_factory=list)
    useragent: Optional[str] = None
    dtmfmode: Optional[str] = None


@dataclass
class SipPeer:
    name: str
    enabled: bool = True  # False if section header commented
    kv: Dict[str, List[str]] = field(default_factory=dict)  # allow repeated keys

    def get1(self, key: str) -> Optional[str]:
        vals = self.kv.get(key.lower())
        return vals[0] if vals else None

    def getall(self, key: str) -> List[str]:
        return self.kv.get(key.lower(), [])


def parse_sip_conf(text: str) -> Tuple[SipGlobals, List[str], List[SipPeer]]:
    g = SipGlobals()
    register_lines: List[str] = []
    peers: List[SipPeer] = []
    cur: Optional[SipPeer] = None

    for raw in text.splitlines():
        line = raw.rstrip("\n")

        mreg = REGISTER_RE.match(line)
        if mreg and cur is None:
            register_lines.append(mreg.group(1).strip())
            continue

        msec = SECTION_RE.match(line)
        if msec:
            commented = bool(msec.group(1))
            name = msec.group(2).strip()
            cur = SipPeer(name=name, enabled=(not commented))
            peers.append(cur)
            continue

        # globals (only when not in a section)
        if cur is None:
            mkv = KV_RE.match(line)
            if not mkv:
                continue
            k = mkv.group(1).strip().lower()
            v = mkv.group(2).strip()
            if k == "externip":
                # externip can be ip or ip:port
                if ":" in v:
                    ip, port = v.split(":", 1)
                    g.externip = (ip.strip(), int(port.strip()))
                else:
                    g.externip = (v.strip(), 5060)
            elif k == "localnet":
                g.localnet.append(v)
            elif k == "useragent":
                g.useragent = v
            elif k == "dtmfmode":
                g.dtmfmode = v
            continue

        # inside section: parse key=val even if section is disabled
        mkv = KV_RE.match(line) or KV_COMMENTED_RE.match(line)
        if not mkv:
            continue
        k = mkv.group(1).strip().lower()
        v = mkv.group(2).strip()
        cur.kv.setdefault(k, []).append(v)

    return g, register_lines, peers


def dtmf_sip_to_pjsip(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = v.strip().lower()
    if v == "rfc2833":
        return "rfc4733"
    if v in ("inband", "info", "auto"):
        return v
    return None


def render_lines(lines: List[str], enabled: bool) -> str:
    if enabled:
        return "\n".join(lines) + "\n"
    out = []
    for ln in lines:
        out.append((";" + ln) if ln.strip() else ";")
    return "\n".join(out) + "\n"


def normalize_host(h: Optional[str]) -> Optional[str]:
    if not h:
        return None
    h = h.strip().lower()
    if h == "dynamic":
        return None
    return h


def best_peer_for_registration(reg: Dict[str, str], peers: List[SipPeer]) -> Optional[SipPeer]:
    """
    Try to map register user@host to a sip.conf peer section.

    Heuristics (priority):
      1) peer.host == reg.host AND (peer.defaultuser OR peer.fromuser OR peer.name) == reg.user
      2) (peer.host == reg.host OR peer.fromdomain == reg.host) AND defaultuser/fromuser/name == reg.user
      3) fallback: any peer where defaultuser/fromuser/name == reg.user
    """
    reg_host = reg.get("host", "").strip().lower()
    reg_user = reg.get("user", "").strip()

    candidates_1: List[SipPeer] = []
    candidates_2: List[SipPeer] = []
    candidates_3: List[SipPeer] = []

    for p in peers:
        phost = normalize_host(p.get1("host"))
        p_fromdomain = (p.get1("fromdomain") or "").strip().lower()
        p_user = p.get1("defaultuser") or p.get1("fromuser") or p.name

        if p_user == reg_user:
            candidates_3.append(p)

        if phost and phost == reg_host and p_user == reg_user:
            candidates_1.append(p)
            continue

        if (phost and phost == reg_host and p_user == reg_user) or (
            p_fromdomain and p_fromdomain == reg_host and p_user == reg_user
        ):
            candidates_2.append(p)

    if candidates_1:
        return candidates_1[0]
    if candidates_2:
        return candidates_2[0]
    if candidates_3:
        return candidates_3[0]
    return None


def convert_peer(peer: SipPeer, default_user_agent: Optional[str], default_dtmf: Optional[str]) -> str:
    name = peer.name

    host = peer.get1("host")
    port = peer.get1("port") or "5060"
    context = peer.get1("context")
    allow = peer.get1("allow")
    disallow = peer.get1("disallow")
    dtmfmode = peer.get1("dtmfmode") or default_dtmf
    dtmf_mode = dtmf_sip_to_pjsip(dtmfmode) or "rfc4733"

    directmedia = peer.get1("directmedia") or peer.get1("canreinvite")
    direct_media = normalize_bool(directmedia) if directmedia else None

    defaultuser = peer.get1("defaultuser") or peer.get1("fromuser")
    secret = peer.get1("secret")
    fromuser = peer.get1("fromuser")
    fromdomain = peer.get1("fromdomain")

    qualify = peer.get1("qualify")

    deny = peer.get1("deny")
    permits = peer.getall("permit")

    lines: List[str] = []

    # endpoint
    lines.append(f"[{name}](endpoint-defaults)")
    lines.append("type=endpoint")
    if context:
        lines.append(f"context={context}")
    if disallow:
        lines.append(f"disallow={disallow}")
    if allow:
        lines.append(f"allow={allow}")
    lines.append(f"dtmf_mode={dtmf_mode}")

    # Prefer setting user_agent on endpoint-defaults template; do not duplicate unless you want overrides.
    # if default_user_agent:
    #     lines.append(f"user_agent={default_user_agent}")

    if direct_media is not None:
        lines.append(f"direct_media={'yes' if direct_media else 'no'}")

    if fromuser:
        lines.append(f"from_user={fromuser}")
    if fromdomain:
        lines.append(f"from_domain={fromdomain}")

    lines.append(f"aors={name}")

    # outbound_auth if we have secret + username-ish
    if secret and defaultuser:
        lines.append(f"outbound_auth={name}")

    if qualify and qualify.lower() not in ("no", "false", "0"):
        lines.append("qualify_frequency=60")

    # ACL for static peers with permit/deny
    if deny or permits:
        lines.append(f"acl={name}_acl")

    lines.append("")

    # aor
    lines.append(f"[{name}]")
    lines.append("type=aor")
    if host and host.lower() != "dynamic":
        lines.append(f"contact=sip:{host}:{port}")
    else:
        lines.append("max_contacts=1")
        lines.append("remove_existing=yes")
    lines.append("")

    # outbound_auth (for trunks / peers that have secret)
    if secret and defaultuser:
        lines.append(f"[{name}]")
        lines.append("type=outbound_auth")
        lines.append("auth_type=userpass")
        lines.append(f"username={defaultuser}")
        lines.append(f"password={secret}")
        lines.append("")

    # identify for static peers and domain trunks
    if host and host.lower() != "dynamic":
        lines.append(f"[{name}]")
        lines.append("type=identify")
        lines.append(f"endpoint={name}")
        lines.append(f"match={host}")
        lines.append("")

    # acl object
    if deny or permits:
        lines.append(f"[{name}_acl]")
        lines.append("type=acl")
        if deny:
            lines.append(f"deny={deny}")
        for p in permits:
            lines.append(f"permit={p}")
        lines.append("")

    return render_lines(lines, peer.enabled)


def parse_register(spec: str) -> Dict[str, str]:
    """
    Pragmatic parse of: user:pass@host:port/contact~expires

    Example:
      00076227:password@sip.telphin.com:5060/3097384~360
    """
    out: Dict[str, str] = {"raw": spec}

    expires = None
    if "~" in spec:
        spec, expires = spec.rsplit("~", 1)
        expires = expires.strip()

    contact_user = None
    if "/" in spec:
        left, contact_user = spec.split("/", 1)
        contact_user = contact_user.strip()
    else:
        left = spec

    m = re.match(
        r"^(?P<user>[^:]+):(?P<pass>[^@]+)@(?P<host>[^:]+)(:(?P<port>\d+))?$",
        left.strip(),
    )
    if not m:
        out["parse_error"] = "unrecognized register format"
        return out

    out["user"] = m.group("user")
    out["pass"] = m.group("pass")
    out["host"] = m.group("host")
    out["port"] = m.group("port") or "5060"
    if contact_user:
        out["contact_user"] = contact_user
    if expires:
        out["expires"] = expires
    return out


def render_registration(reg_name: str, outbound_auth_name: str, reg: Dict[str, str]) -> str:
    host = reg["host"]
    port = reg["port"]
    user = reg["user"]
    contact_user = reg.get("contact_user")
    expires = reg.get("expires", "360")

    lines: List[str] = []
    lines.append(f"[{reg_name}]")
    lines.append("type=registration")
    lines.append("transport=transport-udp")
    lines.append(f"outbound_auth={outbound_auth_name}")
    lines.append(f"server_uri=sip:{host}:{port}")
    lines.append(f"client_uri=sip:{user}@{host}")
    if contact_user:
        lines.append(f"contact_user={contact_user}")
    lines.append(f"expiration={expires}")
    lines.append("retry_interval=60")
    lines.append("forbidden_retry_interval=600")
    lines.append("fatal_retry_interval=0")
    lines.append("")
    return "\n".join(lines) + "\n"


def generate(text: str) -> str:
    g, registers, peers = parse_sip_conf(text)

    ext_ip = g.externip[0] if g.externip else None
    ext_port = g.externip[1] if g.externip else 5060

    default_dtmf = g.dtmfmode
    default_user_agent = g.useragent

    out: List[str] = []
    out.append("; ===== GENERATED PJSIP CONFIG (from sip.conf) =====")
    out.append("")

    # transport
    out.append("; ===== TRANSPORTS =====")
    out.append("[transport-udp]")
    out.append("type=transport")
    out.append("protocol=udp")
    out.append("bind=0.0.0.0:5060")
    if ext_ip:
        out.append(f"external_signaling_address={ext_ip}")
        out.append(f"external_signaling_port={ext_port}")
    for ln in g.localnet:
        out.append(f"local_net={ln}")
    out.append("")

    # template
    out.append("; ===== TEMPLATES =====")
    out.append("[endpoint-defaults](!)")
    out.append("type=endpoint")
    out.append("transport=transport-udp")
    if default_user_agent:
        out.append(f"user_agent={default_user_agent}")
    out.append(f"dtmf_mode={dtmf_sip_to_pjsip(default_dtmf) or 'rfc4733'}")
    out.append("direct_media=no")
    out.append("")

    # peers
    out.append("; ===== PEERS/TRUNKS =====")
    for p in peers:
        out.append(convert_peer(p, default_user_agent, default_dtmf))

    # register lines -> link to matching peers
    out.append("; ===== REGISTRATIONS (from register =>) =====")
    for idx, rline in enumerate(registers, 1):
        reg = parse_register(rline)
        if "parse_error" in reg:
            out.append(f"; could not parse register line: {rline}")
            continue

        peer = best_peer_for_registration(reg, peers)

        if peer:
            outbound_auth_name = peer.name
            reg_name = f"{peer.name}_reg"
            enabled = peer.enabled
        else:
            # fallback deterministic name if no match
            outbound_auth_name = f"reg_{idx}_{reg['user']}_{reg['host']}".replace(".", "_")
            reg_name = f"{outbound_auth_name}_reg"
            enabled = True

            # must create outbound_auth for orphan registrations
            auth_lines = [
                f"[{outbound_auth_name}]",
                "type=outbound_auth",
                "auth_type=userpass",
                f"username={reg['user']}",
                f"password={reg['pass']}",
                "",
            ]
            out.append(render_lines(auth_lines, enabled))

        reg_block = render_registration(reg_name, outbound_auth_name, reg)
        out.append(render_lines(reg_block.splitlines(), enabled))

    out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    import sys

    sip_path = sys.argv[1] if len(sys.argv) > 1 else "sip.conf"
    with open(sip_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    print(generate(text))
