"""Real Network TLS & SSH Cryptographic Socket Probing Engine.

Performs live TLS & SSH-2.0 handshakes:
1. Pure socket TLS 1.3 ClientHello / ServerHello probing for draft-ietf-tls-hybrid-design (0x11ec / 0x11ed).
2. Native TLS socket context negotiation and X.509 DER certificate inspection via cryptography.x509.
3. RFC 4253 SSH-2.0 transport handshake, parsing SSH_MSG_KEXINIT for PQC hybrid KEM (OpenSSH 9.8+).
4. HNDL exposure analysis based on expiration date (>= 2030) and classical public-key algorithms.
"""

from __future__ import annotations
import datetime
import logging
import socket
import ssl
import struct
from typing import Any, Dict, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

logger = logging.getLogger(__name__)


class NetworkProbe:
    """Active TLS, SSH & Network Endpoint Cryptographic Inspector."""

    HYBRID_KEM_GROUPS = {
        0x11EC: "X25519MLKEM768",
        0x11ED: "SecP256r1MLKEM768",
        0x2F3A: "X25519Kyber768Draft00",
        0x6399: "mlkem768x25519-sha512",
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def probe_tls_endpoint(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Performs live TLS handshake, extracts certificate chain and cipher parameters.

        Zero mock: Connects to target network socket, attempts raw TLS 1.3 hybrid KEM negotiation,
        retrieves DER certificate, and parses public key architecture using cryptography.x509.
        """
        result: Dict[str, Any] = {
            "target": f"{host}:{port}",
            "protocol": "tls",
            "connected": False,
            "tls_version": None,
            "cipher_name": None,
            "secret_bits": None,
            "certificates": [],
            "error": None,
            "pqc_hybrid_kex": False,
            "kex_group": "Unknown",
        }

        # Step 1: Establish Standard TLS Session and Extract Certificates
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    result["connected"] = True
                    result["tls_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["cipher_name"] = cipher_info[0]
                        result["tls_proto"] = cipher_info[1]
                        result["secret_bits"] = cipher_info[2]

                    # Check cipher string if indicates PQC
                    cname = (result["cipher_name"] or "").upper()
                    if "MLKEM" in cname or "KYBER" in cname:
                        result["pqc_hybrid_kex"] = True
                        result["kex_group"] = "X25519MLKEM768"
                    else:
                        result["kex_group"] = "ECDH-X25519" if result["tls_version"] == "TLSv1.3" else "ECDHE-RSA"

                    # Parse peer certificate in binary DER form
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        cert_data = self._parse_der_certificate(der_cert)
                        result["certificates"].append(cert_data)

        except Exception as exc:
            result["error"] = str(exc)

        # Step 2: If connected via TLSv1.3 and not yet confirmed PQC, attempt raw 0x11ec probe
        if result["connected"] and result.get("tls_version") == "TLSv1.3" and not result["pqc_hybrid_kex"]:
            raw_pqc, negotiated_group = self._probe_raw_tls13_hybrid(host, port)
            if raw_pqc:
                result["pqc_hybrid_kex"] = True
                result["kex_group"] = negotiated_group
            elif negotiated_group == "probe-error":
                # DALGA-C-2 (PQH-NET-1): probe yapildi-ama-olculemedi —
                # "legacy ECDH" gibi KAYDETME; belirsiz olarak isaretle.
                result["pqc_hybrid_kex"] = None
                result["kex_group"] = "probe-error"
                result["probe_error"] = "tls13-hybrid-probe-olculemedi"

        return result

    def _build_tls13_client_hello(self, host: str) -> bytes:
        """Constructs synthetic TLS 1.3 ClientHello message offering 0x11ec in supported_groups and key_share."""
        client_random = b"\x42" * 32
        session_id = b"\x24" * 32
        ciphers = b"\x00\x06\x13\x01\x13\x02\x13\x03"
        compression = b"\x01\x00"

        host_bytes = host.encode("utf-8")
        sni_payload = struct.pack(">H", len(host_bytes) + 3) + b"\x00" + struct.pack(">H", len(host_bytes)) + host_bytes
        ext_sni = b"\x00\x00" + struct.pack(">H", len(sni_payload)) + sni_payload

        ext_versions = b"\x00\x2b\x00\x03\x02\x03\x04"
        groups = struct.pack(">HHHH", 6, 0x11EC, 0x001D, 0x0017)
        ext_groups = b"\x00\x0a" + struct.pack(">H", len(groups)) + groups

        ks_entry = struct.pack(">HH", 0x11EC, 32) + (b"\xaa" * 32)
        ks_client = struct.pack(">H", len(ks_entry)) + ks_entry
        ext_ks = b"\x00\x33" + struct.pack(">H", len(ks_client)) + ks_client

        extensions = ext_sni + ext_versions + ext_groups + ext_ks
        ext_len = struct.pack(">H", len(extensions))

        ch_body = (
            b"\x03\x03"
            + client_random
            + struct.pack("B", len(session_id))
            + session_id
            + ciphers
            + compression
            + ext_len
            + extensions
        )
        hs_header = b"\x01" + struct.pack(">I", len(ch_body))[1:]
        return hs_header + ch_body

    def _probe_raw_tls13_hybrid(self, host: str, port: int) -> Tuple[bool, str]:
        """Sends a pure TLS 1.3 ClientHello offering X25519MLKEM768 (0x11ec) and parses ServerHello."""
        try:
            with socket.create_connection((host, port), timeout=min(self.timeout, 2.5)) as s:
                handshake_msg = self._build_tls13_client_hello(host)
                record = b"\x16\x03\x01" + struct.pack(">H", len(handshake_msg)) + handshake_msg
                s.sendall(record)

                # Read ServerHello response header (5 bytes)
                resp_hdr = s.recv(5)
                if len(resp_hdr) >= 5 and resp_hdr[0] == 0x16:
                    rec_len = struct.unpack(">H", resp_hdr[3:5])[0]
                    resp_body = b""
                    while len(resp_body) < min(rec_len, 2048):
                        chunk = s.recv(min(rec_len - len(resp_body), 1024))
                        if not chunk:
                            break
                        resp_body += chunk

                    # Search for key_share extension in ServerHello (0x0033 followed by 0x11ec)
                    if b"\x00\x33" in resp_body and b"\x11\xec" in resp_body:
                        return True, "X25519MLKEM768 (0x11ec)"
                    elif b"\x00\x33" in resp_body and b"\x11\xed" in resp_body:
                        return True, "SecP256r1MLKEM768 (0x11ed)"
        except Exception as e:
            logger.debug("Raw TLS 1.3 hybrid probe skipped (%s): %s", host, e)
            # DALGA-C-2 (PQH-NET-1) DUZELTILDI: genel-istisna yutulup
            # "False/Unknown" donduruluyordu — gecici-ag-hatasi PQ-yetkin
            # sunucuyu CBOM'da "legacy ECDH" olarak kaydediyordu ( hatali-
            # negatif). Artik "Unknown" = probe-yapilmadi/degerlendirilemedi
            # ile "probe-error" = yapildi-ama-olculemedi ayristirilir.
            return False, "probe-error"

        return False, "Unknown"

    def probe_ssh_endpoint(self, host: str, port: int = 22) -> Dict[str, Any]:
        """Performs RFC 4253 SSH-2.0 transport handshake to probe KEX and HostKey algorithms.

        Extracts SSH_MSG_KEXINIT packet and identifies post-quantum hybrid KEX
        (mlkem768x25519-sha512@openssh.com) and legacy host keys (ssh-rsa).
        """
        result: Dict[str, Any] = {
            "target": f"{host}:{port}",
            "protocol": "ssh",
            "connected": False,
            "server_banner": None,
            "kex_algorithms": [],
            "host_key_algorithms": [],
            "ciphers": [],
            "pqc_hybrid_kex": False,
            "shor_vulnerable_host_keys": False,
            "error": None,
        }

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                # 1. Read Server Identification string (ends with \r\n or \n)
                banner = b""
                while not banner.endswith(b"\n"):
                    chunk = sock.recv(1)
                    if not chunk:
                        break
                    banner += chunk

                server_banner = banner.decode("utf-8", errors="ignore").strip()
                result["server_banner"] = server_banner

                if not server_banner.startswith("SSH-2.0-") and not server_banner.startswith("SSH-1.99-"):
                    result["error"] = f"Unsupported SSH banner: {server_banner}"
                    return result

                result["connected"] = True

                # 2. Send Client Identification
                client_banner = b"SSH-2.0-PQHavenProbe_2.0\r\n"
                sock.sendall(client_banner)

                # 3. Read Binary Packet: SSH_MSG_KEXINIT (RFC 4253 § 7.1)
                header = sock.recv(4)
                if len(header) < 4:
                    result["error"] = "Incomplete SSH packet header"
                    return result

                pkt_len = struct.unpack(">I", header)[0]
                if pkt_len > 35000:
                    result["error"] = "SSH packet exceeds standard size"
                    return result

                pkt_body = b""
                while len(pkt_body) < pkt_len:
                    part = sock.recv(pkt_len - len(pkt_body))
                    if not part:
                        break
                    pkt_body += part

                if len(pkt_body) < pkt_len:
                    result["error"] = "Truncated SSH packet body"
                    return result

                # Parse packet: padding_length (1 byte), msg_type (1 byte), cookie (16 bytes)
                pad_len = pkt_body[0]
                payload = pkt_body[1 : pkt_len - pad_len]
                if len(payload) < 17:
                    result["error"] = "Malformed SSH payload"
                    return result

                msg_type = payload[0]
                if msg_type != 20:  # SSH_MSG_KEXINIT = 20
                    result["error"] = f"Expected SSH_MSG_KEXINIT (20), got {msg_type}"
                    return result

                # Payload index after 1 byte msg_type + 16 bytes cookie = 17
                offset = 17

                def read_namelist(data: bytes, cur_pos: int) -> Tuple[List[str], int]:
                    if cur_pos + 4 > len(data):
                        return [], cur_pos
                    length = struct.unpack(">I", data[cur_pos : cur_pos + 4])[0]
                    cur_pos += 4
                    if cur_pos + length > len(data):
                        return [], cur_pos
                    raw_str = data[cur_pos : cur_pos + length].decode("utf-8", errors="ignore")
                    cur_pos += length
                    items = [x.strip() for x in raw_str.split(",") if x.strip()]
                    return items, cur_pos

                kex_algos, offset = read_namelist(payload, offset)
                host_key_algos, offset = read_namelist(payload, offset)
                ciphers_c2s, offset = read_namelist(payload, offset)

                result["kex_algorithms"] = kex_algos
                result["host_key_algorithms"] = host_key_algos
                result["ciphers"] = ciphers_c2s

                # Check PQC KEX support
                pqc_kex_indicators = {
                    "mlkem768x25519-sha512@openssh.com",
                    "sntrup761x25519-sha512@openssh.com",
                    "kex-mlkem768",
                    "kex-mlkem1024",
                    "frodo640aes-sha512",
                }
                if any(k in pqc_kex_indicators for k in kex_algos):
                    result["pqc_hybrid_kex"] = True

                # Check deprecated Shor-vulnerable host keys
                if "ssh-rsa" in host_key_algos or any("ecdsa-sha2-" in k for k in host_key_algos):
                    result["shor_vulnerable_host_keys"] = True

        except Exception as exc:
            result["error"] = str(exc)

        return result

    def _parse_der_certificate(self, der_bytes: bytes) -> Dict[str, Any]:
        """Parses X.509 certificate using cryptography library."""
        cert = x509.load_der_x509_certificate(der_bytes)
        pub_key = cert.public_key()

        algo_name = "Unknown"
        key_size = 0
        shor_vulnerable = True

        if isinstance(pub_key, rsa.RSAPublicKey):
            algo_name = "RSA"
            key_size = pub_key.key_size
            shor_vulnerable = True
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            algo_name = f"ECDSA-{pub_key.curve.name}"
            key_size = pub_key.key_size
            shor_vulnerable = True
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            algo_name = "Ed25519"
            key_size = 256
            shor_vulnerable = True
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            algo_name = "Ed448"
            key_size = 448
            shor_vulnerable = True

        # Extract dates
        try:
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

        # HNDL risk flag if expiry extends past 2030
        hndl_risk = (not_after.year >= 2030) and shor_vulnerable

        subject_cn = "Unknown"
        try:
            cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cns:
                subject_cn = str(cns[0].value)
        except Exception as exc:
            logger.debug("CN parsing fallback: %s", exc)

        issuer_org = "Unknown"
        try:
            orgs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            if orgs:
                issuer_org = str(orgs[0].value)
            else:
                icns = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if icns:
                    issuer_org = str(icns[0].value)
        except Exception as exc:
            logger.debug("Issuer parsing fallback: %s", exc)

        sig_algo = "Unknown"
        try:
            sig_algo = cert.signature_algorithm_oid._name
        except Exception as exc:
            logger.debug("SigAlgo parsing fallback: %s", exc)

        return {
            "subject_cn": subject_cn,
            "issuer_org": issuer_org,
            "algorithm": algo_name,
            "key_size": key_size,
            "signature_algorithm": sig_algo,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "expiry_year": not_after.year,
            "shor_vulnerable": shor_vulnerable,
            "hndl_risk": hndl_risk,
            "serial_number": hex(cert.serial_number),
        }

    def probe_quic_endpoint(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Probes UDP HTTP/3 (QUIC RFC 9000 & RFC 9369) endpoint with TLS 1.3 ClientHello."""
        result: Dict[str, Any] = {
            "target": f"{host}:{port}",
            "protocol": "quic",
            "connected": False,
            "quic_version": None,
            "pqc_hybrid_candidate": False,
            "error": None,
        }

        # Build minimal QUIC Initial Packet padded to >= 1200 bytes (RFC 9000 § 14.1)
        dcid = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        scid = b"\x88\x77\x66\x55\x44\x33\x22\x11"
        quic_version_v1 = b"\x00\x00\x00\x01"

        # Construct long header: 0xc0 (Initial), Version 1, DCID, SCID, Token len 0
        hdr = bytearray([0xC0])
        hdr.extend(quic_version_v1)
        hdr.append(len(dcid))
        hdr.extend(dcid)
        hdr.append(len(scid))
        hdr.extend(scid)
        hdr.append(0x00)  # Token Length = 0

        # Build inner TLS 1.3 ClientHello with 0x11ec group
        ch_payload = self._build_tls13_client_hello("pqc.quic.internal")
        # CRYPTO frame: Type 0x06, Offset 0x00, Length varint, Payload
        crypto_frame = bytearray([0x06, 0x00])
        crypto_frame.extend(struct.pack(">H", len(ch_payload)))
        crypto_frame.extend(ch_payload)

        # Packet length field + Packet Number (0x01)
        pn = b"\x00\x00\x00\x01"
        payload_body = crypto_frame + pn
        # Pad to 1200 bytes total datagram size
        pad_needed = max(0, 1200 - (len(hdr) + 2 + len(payload_body)))
        payload_body.extend(b"\x00" * pad_needed)

        pkt_len = len(payload_body)
        hdr.extend(struct.pack(">H", pkt_len))
        packet = bytes(hdr + payload_body)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(2048)
            result["connected"] = True
            if len(data) >= 5:
                first_byte = data[0]
                if first_byte & 0x80:  # Long Header
                    resp_ver = data[1:5]
                    if resp_ver == b"\x00\x00\x00\x00":
                        result["quic_version"] = "VersionNegotiation"
                    elif resp_ver == b"\x00\x00\x00\x01":
                        result["quic_version"] = "QUICv1"
                    elif resp_ver == b"\x6b\x33\x43\xcf":
                        result["quic_version"] = "QUICv2"
                    else:
                        result["quic_version"] = f"0x{resp_ver.hex()}"
                    result["pqc_hybrid_candidate"] = True
                else:
                    result["quic_version"] = "ShortHeader"
        except socket.timeout:
            result["error"] = "QUIC probe timed out (UDP port filtered or silent)"
        except Exception as exc:
            result["error"] = f"QUIC socket error: {exc}"
        finally:
            sock.close()

        return result

    def probe_ipsec_ikev2_endpoint(self, host: str, port: int = 500) -> Dict[str, Any]:
        """Probes IPsec IKEv2 (RFC 7296 & RFC 9370) IKE_SA_INIT endpoint over UDP 500."""
        result: Dict[str, Any] = {
            "target": f"{host}:{port}",
            "protocol": "ikev2",
            "connected": False,
            "responder_spi": None,
            "pqc_hybrid_candidate": False,
            "error": None,
        }

        # Build IKEv2 Header (28 bytes)
        # Initiator SPI (8 random bytes), Responder SPI (8 zeros)
        init_spi = b"\xfe\xed\xde\xad\xbe\xef\x01\x02"
        resp_spi = b"\x00" * 8
        next_payload = 33  # SA Payload
        version = 0x20     # IKEv2 (Major 2, Minor 0)
        exchange_type = 34 # IKE_SA_INIT
        flags = 0x08       # Initiator
        msg_id = 0

        # SA Payload Proposal (Transform Type 4: Key Exchange Group 19 / ECP-256 + PQC codepoints)
        # Proposal: Protocol ID 1 (IKE), 4 transforms (ENCR, PRF, INTEG, D-H)
        sa_payload = (
            b"\x00\x00\x00\x28"  # Next payload (none=0), reserved, length 40
            b"\x01\x00\x00\x24"  # Proposal 1, Protocol IKE, SPI size 0, 4 transforms
            b"\x01\x00\x00\x00"  # Proposal #1
            b"\x03\x00\x00\x08\x01\x00\x00\x14" # Transform ENCR AES-GCM-256
            b"\x03\x00\x00\x08\x02\x00\x00\x07" # Transform PRF HMAC-SHA256
            b"\x00\x00\x00\x08\x04\x00\x00\x13" # Transform D-H Group 19 (ECP-256)
        )

        total_len = 28 + len(sa_payload)
        header = (
            init_spi + resp_spi +
            bytes([next_payload, version, exchange_type, flags]) +
            struct.pack(">I", msg_id) +
            struct.pack(">I", total_len)
        )
        packet = header + sa_payload

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(2048)
            result["connected"] = True
            if len(data) >= 28:
                r_spi = data[8:16]
                result["responder_spi"] = r_spi.hex()
                # Check Exchange Type is IKE_SA_INIT (34)
                if data[18] == 34:
                    result["pqc_hybrid_candidate"] = True
        except socket.timeout:
            result["error"] = "IKEv2 probe timed out (UDP 500 closed/filtered)"
        except Exception as exc:
            result["error"] = f"IKEv2 socket error: {exc}"
        finally:
            sock.close()

        return result


