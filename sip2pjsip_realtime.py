#!/usr/bin/env python3
"""
sip2pjsip_realtime.py
~~~~~~~~~~~~~~~~~~~~~
Migrate chan_sip realtime peers from the ``sip_friends`` table into the
corresponding PJSIP realtime tables:

  - ps_endpoints
  - ps_aors
  - ps_auths         (when a secret is present)
  - ps_registrations (for static-host peers that carry credentials)

The field-mapping logic mirrors ``sip2pjsip.py`` so both tools produce
consistent results.

Usage
-----
  python sip2pjsip_realtime.py [options]

Options
-------
  --host HOST            MySQL server hostname (default: 127.0.0.1)
  --port PORT            MySQL server port     (default: 3306)
  --user USER            MySQL username        (default: asterisk)
  --password PASSWORD    MySQL password        (default: "")
  --db DATABASE          MySQL database name   (default: asterisk)
  --src-table TABLE      Source table          (default: sip_friends)
  --default-transport T  Default PJSIP transport to assign to endpoints
                         (default: transport-udp)
  --dry-run              Print SQL statements instead of executing them
  --skip-existing        Use INSERT IGNORE so existing rows are left intact
  --verbose              Print each peer name as it is processed
"""

import argparse
import re
import sys
from typing import Dict, List, Optional

try:
    import pymysql
    import pymysql.cursors
except ImportError:
    print(
        "pymysql is required.  Install it with:  pip install pymysql",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Field-mapping helpers (ported from sip2pjsip.py)
# ---------------------------------------------------------------------------

def _normalize_bool(v: Optional[str]) -> Optional[bool]:
    if not v:
        return None
    v = v.strip().lower()
    if v in ("yes", "true", "1", "on"):
        return True
    if v in ("no", "false", "0", "off"):
        return False
    return None


def _dtmf_to_pjsip(v: Optional[str]) -> str:
    """Convert chan_sip dtmfmode value to the PJSIP equivalent."""
    if not v:
        return "rfc4733"
    v = v.strip().lower()
    if v == "rfc2833":
        return "rfc4733"
    if v in ("inband", "info", "auto"):
        return v
    return "rfc4733"


# Safe pattern for table names: letters, digits, underscores only.
_TABLE_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")

# Default registration timer values (seconds).
_REG_EXPIRATION             = "360"
_REG_RETRY_INTERVAL         = "60"
_REG_FORBIDDEN_RETRY_INTERVAL = "600"
_REG_FATAL_RETRY_INTERVAL   = "0"

_TRANSPORT_MAP = {
    "udp": "transport-udp",
    "tcp": "transport-tcp",
    "tls": "transport-tls",
}


def _qualify_frequency(qualify: Optional[str]) -> Optional[str]:
    """Return qualify_frequency (seconds) from chan_sip qualify value."""
    if not qualify:
        return None
    ql = qualify.strip().lower()
    if ql in ("no", "false", "0", "off"):
        return None
    if ql in ("yes", "true", "on"):
        return "60"
    try:
        return str(max(1, int(qualify) // 1000))
    except ValueError:
        return "60"


# ---------------------------------------------------------------------------
# Core conversion: one sip_friends row -> rows for the four PJSIP tables
# ---------------------------------------------------------------------------

def _row_val(row: Dict, key: str) -> Optional[str]:
    """Return the string value of *key* in *row*, or None if absent/empty."""
    v = row.get(key)
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def convert_row(
    row: Dict,
    default_transport: str,
) -> Dict[str, Optional[Dict[str, str]]]:
    """
    Convert a single sip_friends row to a dict with up to four sub-dicts,
    one per PJSIP table.  A sub-dict value of None means "do not insert".

    Returns::

        {
            "ps_endpoints":     { column: value, ... } or None,
            "ps_aors":          { column: value, ... } or None,
            "ps_auths":         { column: value, ... } or None,
            "ps_registrations": { column: value, ... } or None,
        }
    """
    name        = _row_val(row, "name")
    if not name:
        return {"ps_endpoints": None, "ps_aors": None,
                "ps_auths": None, "ps_registrations": None}

    auth_id = f"{name}-auth"

    context     = _row_val(row, "context")
    allow       = _row_val(row, "allow")
    disallow    = _row_val(row, "disallow")
    dtmfmode    = _row_val(row, "dtmfmode")
    directmedia = _row_val(row, "directmedia") or _row_val(row, "canreinvite")
    defaultuser = _row_val(row, "defaultuser") or _row_val(row, "fromuser")
    fromuser    = _row_val(row, "fromuser")
    fromdomain  = _row_val(row, "fromdomain")
    secret      = _row_val(row, "secret")
    host        = _row_val(row, "host")
    port        = _row_val(row, "port") or "5060"
    qualify     = _row_val(row, "qualify")
    nat         = _row_val(row, "nat")
    insecure    = _row_val(row, "insecure")
    callerid    = _row_val(row, "callerid")
    encryption  = _row_val(row, "encryption")
    outboundprx = _row_val(row, "outboundproxy")
    transport   = _row_val(row, "transport")
    mailbox     = _row_val(row, "mailbox")
    busylevel   = _row_val(row, "busylevel")
    deny        = _row_val(row, "deny")
    permit      = _row_val(row, "permit")

    is_dynamic = (not host) or host.lower() == "dynamic"

    # --- ps_endpoints -------------------------------------------------------
    ep: Dict[str, str] = {"id": name}

    chosen_transport = _TRANSPORT_MAP.get((transport or "").lower(), default_transport)
    ep["transport"] = chosen_transport

    ep["aors"] = name

    if context:
        ep["context"] = context
    if disallow:
        ep["disallow"] = disallow
    if allow:
        ep["allow"] = allow

    ep["dtmf_mode"] = _dtmf_to_pjsip(dtmfmode)

    dm = _normalize_bool(directmedia)
    if dm is not None:
        ep["direct_media"] = "yes" if dm else "no"

    if fromuser:
        ep["from_user"] = fromuser
    if fromdomain:
        ep["from_domain"] = fromdomain
    if callerid:
        ep["callerid"] = callerid

    # nat= mapping
    rtp_symmetric_set = False
    if nat:
        nat_l = nat.strip().lower()
        if nat_l == "yes":
            ep["rtp_symmetric"] = "yes"
            ep["force_rport"]   = "yes"
            ep["rewrite_contact"] = "yes"
            rtp_symmetric_set = True
        elif nat_l == "no":
            ep["rtp_symmetric"] = "no"
            ep["force_rport"]   = "no"
            ep["rewrite_contact"] = "no"
            rtp_symmetric_set = True
        elif nat_l == "force_rport":
            ep["rtp_symmetric"] = "yes"
            ep["force_rport"]   = "yes"
            ep["rewrite_contact"] = "yes"
            rtp_symmetric_set = True
        elif nat_l == "comedia":
            ep["rtp_symmetric"] = "yes"
            rtp_symmetric_set = True

    # insecure= mapping
    insecure_no_auth = False
    if insecure:
        insecure_l = insecure.strip().lower()
        if insecure_l in ("port", "invite,port", "port,invite") and not rtp_symmetric_set:
            ep["rtp_symmetric"] = "yes"
        if insecure_l in ("invite", "yes", "invite,port", "port,invite"):
            insecure_no_auth = True

    # media_encryption= from encryption=
    if encryption:
        enc = _normalize_bool(encryption)
        if enc is True:
            ep["media_encryption"] = "sdes"
        elif enc is False:
            ep["media_encryption"] = "no"

    # auth / outbound_auth
    # Dynamic peers (phones) register *to* Asterisk → use auth= for inbound challenge.
    # Static peers (trunks) have Asterisk register *to* them → use outbound_auth=.
    if secret and defaultuser and not insecure_no_auth:
        if is_dynamic:
            ep["auth"] = auth_id
        else:
            ep["outbound_auth"] = auth_id

    if outboundprx:
        ep["outbound_proxy"] = outboundprx
    if mailbox:
        ep["mailboxes"] = mailbox
    if busylevel:
        ep["device_state_busy_at"] = busylevel
    if deny:
        ep["deny"] = deny
    if permit:
        ep["permit"] = permit

    # --- ps_aors ------------------------------------------------------------
    aor: Dict[str, str] = {"id": name}

    if is_dynamic:
        aor["max_contacts"]    = "1"
        aor["remove_existing"] = "yes"
    else:
        aor["contact"] = f"sip:{host}:{port}"

    qf = _qualify_frequency(qualify)
    if qf:
        aor["qualify_frequency"] = qf

    # --- ps_auths -----------------------------------------------------------
    auth_row: Optional[Dict[str, str]] = None
    if secret and defaultuser:
        auth_row = {
            "id":        auth_id,
            "auth_type": "userpass",
            "username":  defaultuser,
            "password":  secret,
        }

    # --- ps_registrations ---------------------------------------------------
    reg_row: Optional[Dict[str, str]] = None
    if secret and defaultuser and not is_dynamic:
        reg_row = {
            "id":                       f"{name}_reg",
            "transport":                chosen_transport,
            "outbound_auth":            auth_id,
            "server_uri":               f"sip:{host}:{port}",
            "client_uri":               f"sip:{defaultuser}@{host}",
            "expiration":               _REG_EXPIRATION,
            "retry_interval":           _REG_RETRY_INTERVAL,
            "forbidden_retry_interval": _REG_FORBIDDEN_RETRY_INTERVAL,
            "fatal_retry_interval":     _REG_FATAL_RETRY_INTERVAL,
        }

    return {
        "ps_endpoints":     ep,
        "ps_aors":          aor,
        "ps_auths":         auth_row,
        "ps_registrations": reg_row,
    }


# ---------------------------------------------------------------------------
# SQL helpers
# ---------------------------------------------------------------------------

# Columns whose values are redacted in dry-run SQL output to avoid leaking
# credentials in logs or terminal history.
_SENSITIVE_COLS = frozenset({"password", "secret", "md5secret"})


def _build_insert(table: str, row: Dict[str, str], ignore: bool, redact: bool = False) -> str:
    """Build a display-safe INSERT statement.

    Values are single-quote-escaped (``'`` -> ``''``) so that the output is
    safe to copy-paste into a MySQL client.  When *redact* is True the content
    of sensitive columns (``password`` etc.) is replaced with ``[REDACTED]``.
    """
    cols = ", ".join(f"`{c}`" for c in row)
    vals_list: List[str] = []
    for col, val in row.items():
        if redact and col in _SENSITIVE_COLS:
            vals_list.append("'[REDACTED]'")
        else:
            escaped = val.replace("'", "''")
            vals_list.append(f"'{escaped}'")
    vals = ", ".join(vals_list)
    kw   = "INSERT IGNORE" if ignore else "INSERT"
    return f"{kw} INTO `{table}` ({cols}) VALUES ({vals});"


def _execute_or_print(
    cursor,
    table: str,
    row: Dict[str, str],
    ignore: bool,
    dry_run: bool,
) -> None:
    if dry_run:
        # Redact sensitive columns in the printed output so that passwords do
        # not appear in terminal history or CI logs.
        print(_build_insert(table, row, ignore, redact=True))
    else:
        # Use parameterised query for the actual insert to protect against
        # values that contain special characters such as single-quotes.
        cols         = ", ".join(f"`{c}`" for c in row)
        placeholders = ", ".join(["%s"] * len(row))
        kw           = "INSERT IGNORE" if ignore else "INSERT"
        cursor.execute(
            f"{kw} INTO `{table}` ({cols}) VALUES ({placeholders})",
            list(row.values()),
        )


# ---------------------------------------------------------------------------
# Main migration routine
# ---------------------------------------------------------------------------

def migrate(args: argparse.Namespace) -> int:
    """
    Connect to the database, read sip_friends, and write to ps_* tables.
    Returns the number of peers processed.
    """
    conn_kwargs: Dict = {
        "host":    args.host,
        "port":    args.port,
        "user":    args.user,
        "password": args.password,
        "database": args.db,
        "charset":  "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": False,
    }

    try:
        conn = pymysql.connect(**conn_kwargs)
    except pymysql.err.OperationalError as exc:
        print(f"ERROR: Could not connect to MySQL: {exc}", file=sys.stderr)
        return 0

    if not _TABLE_NAME_RE.match(args.src_table):
        print(
            f"ERROR: Invalid source table name '{args.src_table}'. "
            "Only letters, digits and underscores are allowed.",
            file=sys.stderr,
        )
        conn.close()
        return 0

    processed = 0
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM `{args.src_table}`")
            rows = cur.fetchall()

        if args.verbose:
            print(f"Found {len(rows)} row(s) in `{args.src_table}`.")

        if args.dry_run:
            print("-- DRY-RUN: no rows will be written to the database.\n")

        for row in rows:
            name = (row.get("name") or "").strip()
            if not name:
                continue

            if args.verbose:
                print(f"Processing peer: {name}")

            converted = convert_row(row, args.default_transport)

            with conn.cursor() as cur:
                for table in ("ps_endpoints", "ps_aors", "ps_auths", "ps_registrations"):
                    trow = converted.get(table)
                    if trow is None:
                        continue
                    try:
                        _execute_or_print(cur, table, trow, args.skip_existing, args.dry_run)
                    except pymysql.err.IntegrityError as exc:
                        if args.skip_existing:
                            pass  # INSERT IGNORE already silences duplicates
                        else:
                            print(
                                f"WARNING: {table} row for '{name}' "
                                f"already exists or violates a constraint: {exc}",
                                file=sys.stderr,
                            )
                    except pymysql.err.OperationalError as exc:
                        print(
                            f"ERROR: Failed to insert into {table} for peer '{name}': {exc}",
                            file=sys.stderr,
                        )

            processed += 1

        if not args.dry_run:
            conn.commit()
            if args.verbose:
                print(f"\nCommitted {processed} peer(s) to the PJSIP tables.")

    finally:
        conn.close()

    return processed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Migrate chan_sip realtime peers (sip_friends) to PJSIP realtime tables "
            "(ps_endpoints, ps_aors, ps_auths, ps_registrations)."
        )
    )
    p.add_argument("--host",       default="127.0.0.1",    help="MySQL server hostname (default: 127.0.0.1)")
    p.add_argument("--port",       default=3306, type=int, help="MySQL server port (default: 3306)")
    p.add_argument("--user",       default="asterisk",     help="MySQL username (default: asterisk)")
    p.add_argument("--password",   default="",             help="MySQL password")
    p.add_argument("--db",         default="asterisk",     help="MySQL database name (default: asterisk)")
    p.add_argument("--src-table",  default="sip_friends",  help="Source table (default: sip_friends)")
    p.add_argument(
        "--default-transport",
        default="transport-udp",
        help="PJSIP transport to assign when the peer has no transport= (default: transport-udp)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print INSERT statements without executing them",
    )
    p.add_argument(
        "--skip-existing",
        action="store_true",
        help="Use INSERT IGNORE so that already-migrated peers are silently skipped",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each peer name as it is processed",
    )
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    count  = migrate(args)
    if not args.dry_run:
        print(f"Done. {count} peer(s) migrated.")


if __name__ == "__main__":
    main()
