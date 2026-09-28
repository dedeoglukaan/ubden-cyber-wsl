"""Bounded, read-only directory inventory with an explicitly supplied test user.

Beyond object counts, this reads the domain password policy, the machine
account quota, and Domain Admins membership — all standard read-only LDAP reads
that a normal domain user can perform. They feed *draft* findings (weak password
policy, machine-join by any user, excessive domain admins); the analyst confirms
impact before any becomes verified.
"""
from __future__ import annotations

import ssl


def _as_int(entry, field):
    try:
        value = entry[field].value if field in entry else None
    except Exception:
        return None
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _filetime_days(value):
    """AD stores durations as negative 100-nanosecond intervals; return days."""
    if value in (None, 0):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value >= 0:  # 0x7FFFFFFFFFFFFFFF = never / not set
        return None
    return round(abs(value) / (1e7 * 60 * 60 * 24), 1)


def _password_policy(connection, base):
    """Domain root policy attributes; a normal user can read these."""
    try:
        from ldap3 import BASE
        connection.search(base, "(objectClass=domain)", search_scope=BASE,
                          attributes=["minPwdLength", "pwdHistoryLength", "pwdProperties",
                                      "lockoutThreshold", "lockoutDuration", "maxPwdAge",
                                      "minPwdAge", "ms-DS-MachineAccountQuota", "objectSid"],
                          size_limit=1, time_limit=10)
        if not connection.entries:
            return {}, None, None
        entry = connection.entries[0]
        props = _as_int(entry, "pwdProperties")
        policy = {
            "min_length": _as_int(entry, "minPwdLength"),
            "history_length": _as_int(entry, "pwdHistoryLength"),
            "lockout_threshold": _as_int(entry, "lockoutThreshold"),
            "lockout_duration_min": _filetime_days(entry["lockoutDuration"].value
                                                   if "lockoutDuration" in entry else None),
            "max_pwd_age_days": _filetime_days(entry["maxPwdAge"].value
                                               if "maxPwdAge" in entry else None),
            "complexity_enabled": (bool(props & 0x1) if props is not None else None),
        }
        maq = _as_int(entry, "ms-DS-MachineAccountQuota")
        sid = None
        try:
            sid = str(entry["objectSid"].value) if "objectSid" in entry else None
        except Exception:
            sid = None
        return policy, maq, sid
    except Exception:
        return {}, None, None


def _domain_admins(connection, base, domain_sid):
    """Domain Admins membership. Query by sAMAccountName (constant across locales),
    then by RID-512 SID as a fallback — but only when the SID is a valid string SID
    (with get_info=NONE, objectSid can come back as raw bytes, which would make the
    filter invalid and silently drop the whole finding)."""
    filters = ["(sAMAccountName=Domain Admins)"]
    sid = str(domain_sid) if domain_sid else ""
    if sid.upper().startswith("S-1-"):
        filters.append(f"(objectSid={sid}-512)")
    for filt in filters:
        try:
            connection.search(base, f"(&(objectClass=group){filt})",
                              attributes=["member", "sAMAccountName"],
                              size_limit=1, time_limit=10)
        except Exception:
            continue
        if not connection.entries:
            continue
        entry = connection.entries[0]
        members = []
        try:
            raw = entry["member"].values if "member" in entry else []
        except Exception:
            raw = []
        for dn in raw:
            cn = str(dn).split(",", 1)[0]
            members.append(cn[3:] if cn.lower().startswith("cn=") else cn)
        try:
            group = str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "Domain Admins"
        except Exception:
            group = "Domain Admins"
        return {"group": group, "count": len(members), "members": sorted(members)[:60]}
    return None


# Transport ladder: most secure first. Real DCs very often present a self-signed
# LDAPS certificate (or do not publish 636 at all), so strict validation alone
# fails with LDAPSocketOpenError. We degrade gracefully — encrypted-but-unvalidated
# LDAPS, then StartTLS on 389 — and only use plaintext LDAP when the operator opts
# in (it exposes the test-account credential on the wire). Every result records
# which transport succeeded and a security note for the analyst.
TRANSPORTS = (
    ("ldaps_strict", "LDAPS 636 (sertifika doğrulandı)"),
    ("ldaps_insecure", "LDAPS 636 (sertifika DOĞRULANMADI)"),
    ("starttls", "StartTLS 389 (sertifika doğrulanmadı)"),
)
PLAINTEXT = ("plaintext", "Düz metin LDAP 389 (ŞİFRELENMEMİŞ — opt-in)")


def _open(dc, pinned_ip, username, password, mode):
    """Return a bound, read-only ldap3 Connection for the given transport, or raise."""
    from ldap3 import NONE, Connection, Server, Tls
    host = pinned_ip or dc
    common = dict(user=username, password=password, receive_timeout=10,
                  raise_exceptions=True, auto_referrals=False, read_only=True)
    if mode == "ldaps_strict":
        # Bind to the route-checked numeric address; the cert must still name the DC.
        tls = Tls(validate=ssl.CERT_REQUIRED, valid_names=[dc],
                  sni=dc if pinned_ip and pinned_ip != dc else None)
        server = Server(host, port=636, use_ssl=True, get_info=NONE, tls=tls, connect_timeout=5)
        return Connection(server, auto_bind=True, **common)
    if mode == "ldaps_insecure":
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(host, port=636, use_ssl=True, get_info=NONE, tls=tls, connect_timeout=5)
        return Connection(server, auto_bind=True, **common)
    if mode == "starttls":
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(host, port=389, use_ssl=False, get_info=NONE, tls=tls, connect_timeout=5)
        conn = Connection(server, auto_bind=False, **common)
        conn.open(); conn.start_tls(); conn.bind()
        return conn
    server = Server(host, port=389, use_ssl=False, get_info=NONE, connect_timeout=5)
    return Connection(server, auto_bind=True, **common)


def _collect(connection, base, domain, dc):
    from ldap3 import BASE
    outcome = {}
    root_data = {}
    connection.search('', '(objectClass=*)', search_scope=BASE,
                      attributes=['rootDomainNamingContext', 'dnsHostName',
                                  'domainFunctionality', 'forestFunctionality'],
                      size_limit=1, time_limit=5)
    if connection.entries:
        entry = connection.entries[0]
        for field in ('rootDomainNamingContext', 'dnsHostName',
                      'domainFunctionality', 'forestFunctionality'):
            value = entry[field].value if field in entry else None
            root_data[field] = str(value) if value is not None else None
    for label, query in (
        ("users", "(&(objectCategory=person)(objectClass=user))"),
        ("groups", "(objectClass=group)"),
        ("computers", "(objectCategory=computer)"),
    ):
        connection.search(base, query, attributes=["distinguishedName"],
                          size_limit=1000, time_limit=10)
        outcome[label] = {"observed_count": len(connection.entries), "truncated_at": 1000}
    policy, maq, domain_sid = _password_policy(connection, base)
    admins = _domain_admins(connection, base, domain_sid)
    result = {"status": "ok", "domain": domain, "dc": dc, "root_dse": root_data,
              "inventory": outcome}
    if policy:
        result["password_policy"] = policy
    if maq is not None:
        result["machine_account_quota"] = maq
    if admins:
        result["domain_admins"] = admins
    return result


def inspect(dc: str, domain: str, username: str, password: str,
            pinned_ip: str | None = None, allow_plaintext: bool = False) -> dict:
    try:
        import ldap3  # noqa: F401  (probe availability early)
    except ImportError:
        return {"status": "missing_tool", "reason": "ldap3 kurulu degil"}
    if not all((dc, domain, username, password)):
        return {"status": "skipped", "reason": "DC, domain veya test hesabi yok"}
    base = ",".join("DC=" + label for label in domain.lower().split(".") if label)
    if not base or any(not label.replace("-", "").isalnum() for label in domain.split(".")):
        return {"status": "error", "reason": "Gecersiz domain adi"}
    modes = list(TRANSPORTS) + ([PLAINTEXT] if allow_plaintext else [])
    last_reason = ""
    for mode, note in modes:
        try:
            connection = _open(dc, pinned_ip, username, password, mode)
        except Exception as exc:  # transport not available → try the next, less strict one
            last_reason = f"{type(exc).__name__}"
            continue
        try:
            result = _collect(connection, base, domain, dc)
        except Exception as exc:
            last_reason = f"{type(exc).__name__}"
            try: connection.unbind()
            except Exception: pass
            continue
        try: connection.unbind()
        except Exception: pass
        result["transport"] = mode
        result["source"] = note + " · salt okunur test hesabı"
        if mode != "ldaps_strict":
            result["security_warning"] = note
        return result
    return {"status": "error", "domain": domain, "dc": dc,
            "reason": (f"LDAP baglantisi kurulamadi (denenen: {', '.join(m for m, _ in modes)}); "
                       f"son hata: {last_reason or 'bilinmiyor'}. DC'de LDAPS/636 sertifikasi yoksa "
                       "StartTLS/389 denenir; sifrelenmemis LDAP icin ad_allow_plaintext acin.")}
