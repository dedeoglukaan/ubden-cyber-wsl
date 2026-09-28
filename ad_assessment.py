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
    """Domain Admins (RID 512) membership; falls back to the group name."""
    try:
        filt = f"(objectSid={domain_sid}-512)" if domain_sid else "(sAMAccountName=Domain Admins)"
        connection.search(base, f"(&(objectClass=group){filt})",
                          attributes=["member", "sAMAccountName"],
                          size_limit=1, time_limit=10)
        if not connection.entries:
            return None
        entry = connection.entries[0]
        members = []
        try:
            raw = entry["member"].values if "member" in entry else []
        except Exception:
            raw = []
        for dn in raw:
            cn = str(dn).split(",", 1)[0]
            members.append(cn[3:] if cn.lower().startswith("cn=") else cn)
        return {"group": str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "Domain Admins",
                "count": len(members), "members": sorted(members)[:60]}
    except Exception:
        return None


def inspect(dc: str, domain: str, username: str, password: str,
            pinned_ip: str | None = None) -> dict:
    try:
        from ldap3 import BASE, NONE, Connection, Server, Tls
    except ImportError:
        return {"status": "missing_tool", "reason": "ldap3 kurulu degil"}
    if not all((dc, domain, username, password)):
        return {"status": "skipped", "reason": "DC, domain veya test hesabi yok"}
    base = ",".join("DC=" + label for label in domain.lower().split(".") if label)
    if not base or any(not label.replace("-", "").isalnum() for label in domain.split(".")):
        return {"status": "error", "reason": "Gecersiz domain adi"}
    try:
        # Bind to the route-checked numeric address.  The certificate must
        # still identify the operator-supplied DC name.
        tls = Tls(validate=ssl.CERT_REQUIRED, valid_names=[dc],
                  sni=dc if pinned_ip and pinned_ip != dc else None)
        server = Server(pinned_ip or dc, port=636, use_ssl=True, get_info=NONE,
                        tls=tls, connect_timeout=5)
        with Connection(server, user=username, password=password,
                        auto_bind=True, receive_timeout=10, raise_exceptions=True,
                        auto_referrals=False, read_only=True) as connection:
            outcome = {}
            root_data={}
            connection.search('', '(objectClass=*)', search_scope=BASE,
                              attributes=['rootDomainNamingContext','dnsHostName',
                                          'domainFunctionality','forestFunctionality'],
                              size_limit=1,time_limit=5)
            if connection.entries:
                entry=connection.entries[0]
                for field in ('rootDomainNamingContext','dnsHostName',
                              'domainFunctionality','forestFunctionality'):
                    value=entry[field].value if field in entry else None
                    root_data[field]=str(value) if value is not None else None
            for label, query in (
                ("users", "(&(objectCategory=person)(objectClass=user))"),
                ("groups", "(objectClass=group)"),
                ("computers", "(objectCategory=computer)"),
            ):
                connection.search(base, query, attributes=["distinguishedName"],
                                  size_limit=1000, time_limit=10)
                outcome[label] = {"observed_count": len(connection.entries),
                                  "truncated_at": 1000}
            policy, maq, domain_sid = _password_policy(connection, base)
            admins = _domain_admins(connection, base, domain_sid)
            result = {"status": "ok", "domain": domain, "dc": dc,
                      "source": "LDAPS read-only test account", "root_dse": root_data,
                      "inventory": outcome}
            if policy:
                result["password_policy"] = policy
            if maq is not None:
                result["machine_account_quota"] = maq
            if admins:
                result["domain_admins"] = admins
            return result
    except Exception as exc:
        return {"status": "error", "domain": domain, "dc": dc,
                "reason": f"{type(exc).__name__}: LDAPS sorgusu basarisiz"}
