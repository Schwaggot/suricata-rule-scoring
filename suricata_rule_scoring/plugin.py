"""Plugin system for complex scoring logic."""

import importlib
import re
from datetime import date, datetime
from typing import Callable

from suricata_rule_parser import SuricataRule

from .models import ScoringResult

# App-layer keywords that indicate protocol-specific inspection.
# If a rule using ip/tcp has any of these, it's not truly "generic".
# Sourced from Suricata 8.0.3 documentation + legacy underscore forms.
APP_LAYER_KEYWORDS = frozenset({
    # -- HTTP (legacy underscore forms) --
    "http_uri", "http_raw_uri", "http_method", "http_header",
    "http_raw_header", "http_cookie", "http_user_agent",
    "http_host", "http_raw_host", "http_content_type",
    "http_content_len", "http_accept", "http_accept_lang",
    "http_accept_enc", "http_referer", "http_connection",
    "http_request_line", "http_response_line",
    "http_stat_code", "http_stat_msg", "http_server_body",
    "http_client_body", "http_request_body", "http_response_body",
    # -- HTTP (modern dot-notation) --
    "http.uri", "http.uri.raw", "http.method", "http.header",
    "http.header.raw", "http.cookie", "http.user_agent",
    "http.host", "http.host.raw", "http.content_type",
    "http.content_len", "http.accept", "http.accept_lang",
    "http.accept_enc", "http.referer", "http.connection",
    "http.request_line", "http.response_line",
    "http.stat_code", "http.stat_msg",
    "http.request_body", "http.response_body",
    "http.server", "http.location",
    "http.request_header", "http.response_header",
    "http.header_names", "http.protocol", "http.start",
    "urilen",
    # -- File keywords --
    "file_data", "file.data", "file.name", "file.magic",
    "filename", "fileext", "filestore",
    "filemd5", "filesha1", "filesha256", "filesize",
    # -- DNS --
    "dns_query", "dns.query", "dns.opcode", "dns.rcode", "dns.rrtype",
    "dns.queries.rrname", "dns.answers.rrname",
    "dns.authorities.rrname", "dns.additionals.rrname",
    "dns.response.rrname",
    # -- mDNS --
    "mdns.queries.rrname", "mdns.answers.rrname",
    "mdns.authorities.rrname", "mdns.additionals.rrname",
    "mdns.response.rrname",
    # -- TLS/SSL --
    "tls_cert_subject", "tls.cert_subject", "tls_cert_serial",
    "tls.cert_serial", "tls_cert_issuer", "tls.cert_issuer",
    "tls_cert_fingerprint", "tls.cert_fingerprint",
    "tls_cert_notbefore", "tls_cert_notafter",
    "tls_cert_expired", "tls_cert_valid",
    "tls_sni", "tls.sni", "tls.version", "tls.random",
    "tls.subject", "tls.issuerdn",
    "tls.subjectaltname", "tls.certs",
    "tls.random_time", "tls.random_bytes",
    "tls.alpn", "tls.cert_chain_len",
    "tls.fingerprint", "tls.store",
    "ssl_version", "ssl_state",
    # -- JA3/JA4 --
    "ja3_hash", "ja3.hash", "ja3s_hash", "ja3s.hash",
    "ja3_string", "ja3.string", "ja3s_string", "ja3s.string",
    "ja4.hash",
    # -- SSH --
    "ssh_proto", "ssh.proto", "ssh_software", "ssh.software",
    "ssh.protoversion", "ssh.softwareversion",
    "ssh.hassh", "ssh.hassh.string",
    "ssh.hassh.server", "ssh.hassh.server.string",
    # -- SMTP --
    "smtp_cmd", "smtp.cmd",
    "smtp.helo", "smtp.mail_from", "smtp.rcpt_to",
    # -- Email (MIME headers parsed from SMTP/IMAP) --
    "email.from", "email.subject", "email.to", "email.cc",
    "email.date", "email.message_id", "email.x_mailer",
    "email.url", "email.received",
    # -- FTP --
    "ftpdata_command", "ftpbounce",
    "ftp.command", "ftp.command_data", "ftp.completion_code",
    "ftp.dynamic_port", "ftp.mode", "ftp.reply", "ftp.reply_received",
    # -- Modbus --
    "modbus",
    # -- DNP3 --
    "dnp3_data", "dnp3.data", "dnp3_func", "dnp3_ind", "dnp3_obj",
    # -- ENIP/CIP --
    "enip_command", "enip.command",
    "enip.status", "enip.protocol_version",
    "enip.cip_attribute", "enip.cip_instance", "enip.cip_class",
    "enip.cip_extendedstatus", "enip.cip_status",
    "enip.revision", "enip.identity_status", "enip.state",
    "enip.serial", "enip.product_code", "enip.device_type",
    "enip.vendor_id", "enip.product_name", "enip.service_name",
    "enip.capabilities", "cip_service",
    # -- NFS --
    "nfs_procedure", "nfs.procedure", "nfs.version",
    # -- Kerberos --
    "krb5_cname", "krb5.cname",
    "krb5_msg_type", "krb5_sname", "krb5_err_code",
    "krb5.ticket_encryption",
    # -- SIP --
    "sip_method", "sip.method", "sip_uri", "sip.uri",
    "sip.request_line", "sip.response_line", "sip.protocol",
    "sip.stat_code", "sip.stat_msg",
    "sip.from", "sip.to", "sip.via",
    "sip.user_agent", "sip.content_type", "sip.content_length",
    # -- SDP (used within SIP) --
    "sdp.origin", "sdp.session_name", "sdp.session_info",
    "sdp.uri", "sdp.email", "sdp.phone_number",
    "sdp.connection_data", "sdp.bandwidth", "sdp.time",
    "sdp.repeat_time", "sdp.timezone", "sdp.encryption_key",
    "sdp.attribute", "sdp.media.media", "sdp.media.session_info",
    "sdp.media.connection_data", "sdp.media.encryption_key",
    # -- RFB (VNC) --
    "rfb.name", "rfb.secresult", "rfb.sectype",
    # -- RDP --
    "rdp.cookie",
    # -- MQTT --
    "mqtt.type", "mqtt.protocol_version", "mqtt.flags",
    "mqtt.qos", "mqtt.reason_code",
    "mqtt.connack.return_code", "mqtt.connack.session_present",
    "mqtt.connect.clientid", "mqtt.connect.flags",
    "mqtt.connect.password", "mqtt.connect.protocol_string",
    "mqtt.connect.username", "mqtt.connect.willmessage",
    "mqtt.connect.willtopic",
    "mqtt.publish.message", "mqtt.publish.topic",
    "mqtt.subscribe.topic", "mqtt.unsubscribe.topic",
    # -- SNMP --
    "snmp.version", "snmp.community", "snmp.usm", "snmp.pdu_type",
    # -- DCERPC --
    "dcerpc.iface", "dcerpc.opnum", "dcerpc.stub_data",
    # -- SMB --
    "smb.named_pipe", "smb.share",
    "smb.ntlmssp_user", "smb.ntlmssp_domain", "smb.version",
    # -- DHCP --
    "dhcp.leasetime", "dhcp.rebinding_time", "dhcp.renewal_time",
    # -- IKE --
    "ike.init_spi", "ike.resp_spi", "ike.chosen_sa_attribute",
    "ike.exchtype", "ike.vendor",
    "ike.key_exchange_payload", "ike.key_exchange_payload_length",
    "ike.nonce_payload", "ike.nonce_payload_length",
    # -- HTTP/2 --
    "http2.hdr", "http2.data", "http2.pdu",
    "http2.frametype", "http2.errorcode", "http2.priority",
    "http2.window", "http2.size_update", "http2.settings",
    "http2.header_name",
    # -- QUIC --
    "quic.cyu.hash", "quic.cyu.string", "quic.version",
    # -- WebSocket --
    "websocket.payload", "websocket.flags",
    "websocket.mask", "websocket.opcode",
    # -- LDAP --
    "ldap.request.operation", "ldap.responses.operation",
    "ldap.responses.count",
    "ldap.request.dn", "ldap.responses.dn",
    "ldap.responses.result_code", "ldap.responses.message",
    "ldap.request.attribute_type", "ldap.responses.attribute_type",
    # -- PostgreSQL --
    "pgsql.query",
    # -- Generic app-layer --
    "app-layer-protocol", "app-layer-event",
})


def load_plugin(dotted_path: str) -> Callable[[SuricataRule], ScoringResult | None]:
    """Load a plugin callable from a dotted path.

    Supports two formats:
    - "module.path:function_name" (colon separator)
    - "module.path.function_name" (dot separator, last segment is the function)
    """
    if ":" in dotted_path:
        module_path, func_name = dotted_path.rsplit(":", 1)
    else:
        module_path, func_name = dotted_path.rsplit(".", 1)

    module = importlib.import_module(module_path)
    func = getattr(module, func_name)

    if not callable(func):
        raise TypeError(f"Plugin {dotted_path!r} is not callable")

    return func


def compute_content_bytes(content_str: str) -> int:
    """Compute the number of matched bytes in a content string.

    Handles hex blocks like |XX XX| and literal ASCII characters.
    E.g., 'GET |20|/' → 3 (GET) + 1 (hex 20) + 1 (/) = 5 bytes
    """
    total = 0
    # Split into hex blocks and literal segments
    parts = re.split(r"\|([^|]*)\|", content_str)
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Literal text segment
            total += len(part)
        else:
            # Hex block: count hex byte pairs
            hex_bytes = part.strip().split()
            total += len(hex_bytes)
    return total


def builtin_tiny_payload(rule: SuricataRule) -> ScoringResult | None:
    """Check if rule matches fewer than 3 bytes of payload total.

    Quality dimension, weight -10.
    """
    contents = rule.options.content
    if not contents:
        return None

    total_bytes = sum(compute_content_bytes(c) for c in contents)
    if total_bytes < 3:
        return ScoringResult(
            dimension="quality",
            delta=-10,
            reason=f"Rule matches only {total_bytes} bytes of payload (< 3)",
        )
    return None


def builtin_few_content_matches(rule: SuricataRule) -> ScoringResult | None:
    """Check if rule has only 1 content match with fewer than 5 bytes.

    False-positive dimension, weight +8.
    """
    contents = rule.options.content
    if not contents:
        return None

    if len(contents) == 1:
        byte_count = compute_content_bytes(contents[0])
        if byte_count < 5:
            return ScoringResult(
                dimension="false_positive",
                delta=8,
                reason=f"Single content match with only {byte_count} bytes (< 5)",
            )
    return None


def _is_literal(value: str) -> bool:
    """Check if an IP or port value is a literal (not 'any' or a variable)."""
    stripped = value.strip("[]").lstrip("!")
    return stripped.lower() != "any" and not stripped.startswith("$")


def builtin_ip_ioc_rule(rule: SuricataRule) -> ScoringResult | None:
    """Check if rule targets a specific literal IP address (IoC-style detection).

    Quality dimension, weight +10 for IP only, +15 for IP+port.
    """
    has_specific_ip = any(_is_literal(ip) for ip in (rule.header.source_ip, rule.header.dest_ip))
    if not has_specific_ip:
        return None

    has_specific_port = any(_is_literal(p) for p in (rule.header.source_port, rule.header.dest_port))
    if has_specific_port:
        return ScoringResult(
            dimension="quality",
            delta=15,
            reason="Rule targets specific IP address and port (IoC-style detection)",
        )
    return ScoringResult(
        dimension="quality",
        delta=10,
        reason="Rule targets specific IP address (IoC-style detection)",
    )


def _parse_metadata_date(value: str) -> date | None:
    """Parse a date from metadata in YYYY_MM_DD format."""
    try:
        return datetime.strptime(value, "%Y_%m_%d").date()
    except (ValueError, TypeError):
        return None


def builtin_rule_age(rule: SuricataRule) -> ScoringResult | None:
    """Score based on how recently the rule was created or updated.

    Quality dimension, range -5 to +5.
    Looks for updated_at, created_at, or first_seen in metadata.

    Thresholds derived from analysis of ~348K rules across ET Open, ET Pro,
    Stamus, SSLBL, and ThreatFox rulesets:
      < 1 year  → +5   Median last-activity is ~0.9yr; rewards the ~50% of
                        rules that are actively maintained or freshly created.
      1–3 years →  0   Neutral. The 1-2yr and 2-3yr buckets have steady volume
                        (~19% of rules); these aren't neglected yet.
      3–5 years → -3   Clear volume drop-off at 3yr (8.2% → 3.3%). Rules still
                        here are likely not being maintained (~6% of corpus).
      5+ years  → -5   Large stale cluster (~25%) last touched around 2019-2020.
                        Likely targeting obsolete infrastructure or threats.
    """
    metadata = rule.options.metadata
    if not metadata:
        return None

    # Prefer the most-recent-activity date (updated_at > created_at > first_seen)
    best_date = None
    for key in ("updated_at", "created_at", "first_seen"):
        val = metadata.get(key)
        if val is None:
            continue
        parsed = _parse_metadata_date(str(val))
        if parsed is not None and (best_date is None or parsed > best_date):
            best_date = parsed

    if best_date is None:
        return None

    age_days = (date.today() - best_date).days
    if age_days < 0:
        age_days = 0

    if age_days <= 365:
        delta, label = 5, "< 1 year"
    elif age_days <= 1095:
        delta, label = 0, "< 3 years"
    elif age_days <= 1825:
        delta, label = -3, "< 5 years"
    else:
        delta, label = -5, "5+ years"

    if delta == 0:
        return None

    return ScoringResult(
        dimension="quality",
        delta=delta,
        reason=f"Rule age {label} (last activity: {best_date})",
    )


def builtin_generic_protocol(rule: SuricataRule) -> ScoringResult | None:
    """Check if protocol is ip or tcp with no app-layer narrowing.

    False-positive dimension, weight +5.
    """
    protocol = rule.header.protocol.lower()
    if protocol not in ("ip", "tcp"):
        return None

    # Check if any app-layer keyword is used in other_options
    for key in rule.options.other_options:
        if key in APP_LAYER_KEYWORDS:
            return None

    # Also check for app-layer-protocol in other_options (might be stored differently)
    # And check content_modifiers which might reference http/tls buffers
    for modifier in rule.options.content_modifiers:
        for key in modifier:
            if key in APP_LAYER_KEYWORDS:
                return None

    return ScoringResult(
        dimension="false_positive",
        delta=5,
        reason=f"Generic protocol '{protocol}' with no app-layer keyword narrowing",
    )
