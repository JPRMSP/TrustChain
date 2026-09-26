import streamlit as st
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta, timezone
import hashlib


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="TrustChain PKI Lab",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# SESSION STATE
# ============================================================

defaults = {
    "root_key": None,
    "root_cert": None,
    "intermediate_key": None,
    "intermediate_cert": None,
    "certificates": {},
    "revoked": set(),
    "signature": None,
    "signed_message": ""
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# BASIC FUNCTIONS
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def generate_key(algorithm):

    if algorithm == "ECC":
        return ec.generate_private_key(
            ec.SECP256R1()
        )

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def algorithm_name(key):

    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA-2048"

    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ECC / SECP256R1"

    return "Unknown"


def certificate_pem(cert):

    return cert.public_bytes(
        serialization.Encoding.PEM
    ).decode("utf-8")


def fingerprint(cert):

    return cert.fingerprint(
        hashes.SHA256()
    ).hex(":").upper()


def create_name(common_name):

    return x509.Name([
        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            "IN"
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "TrustChain"
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            common_name
        )
    ])


# ============================================================
# KEY SIGNING
# ============================================================

def sign_data(private_key, data):

    if isinstance(private_key, rsa.RSAPrivateKey):

        return private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )


def verify_data(public_key, data, signature):

    try:

        if isinstance(public_key, rsa.RSAPublicKey):

            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

        else:

            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )

        return True

    except Exception:

        return False


# ============================================================
# ROOT CA CREATION
# ============================================================

def create_root_ca(common_name, algorithm):

    key = generate_key(algorithm)

    name = create_name(common_name)

    current = now_utc()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            current - timedelta(minutes=1)
        )
        .not_valid_after(
            current + timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=2
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(
            key,
            hashes.SHA256()
        )
    )

    return key, cert


# ============================================================
# INTERMEDIATE CA
# ============================================================

def create_intermediate_ca(
    root_key,
    root_cert,
    common_name,
    algorithm
):

    key = generate_key(algorithm)

    name = create_name(common_name)

    current = now_utc()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            current - timedelta(minutes=1)
        )
        .not_valid_after(
            current + timedelta(days=1825)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=1
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(
            root_key,
            hashes.SHA256()
        )
    )

    return key, cert


# ============================================================
# END ENTITY CERTIFICATE
# ============================================================

def create_user_certificate(
    issuer_key,
    issuer_cert,
    common_name,
    algorithm
):

    key = generate_key(algorithm)

    name = create_name(common_name)

    current = now_utc()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            current - timedelta(minutes=1)
        )
        .not_valid_after(
            current + timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                key_agreement=True,
                content_commitment=True,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name)
            ]),
            critical=False
        )
        .sign(
            issuer_key,
            hashes.SHA256()
        )
    )

    return key, cert


# ============================================================
# CERTIFICATE SIGNATURE VERIFICATION
# ============================================================

def verify_certificate(cert, issuer_cert):

    try:

        public_key = issuer_cert.public_key()

        if isinstance(
            public_key,
            rsa.RSAPublicKey
        ):

            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )

        else:

            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(
                    cert.signature_hash_algorithm
                )
            )

        return True

    except Exception:

        return False


# ============================================================
# CERTIFICATE STATUS
# ============================================================

def check_certificate(
    cert,
    issuer_cert,
    revoked
):

    signature_ok = verify_certificate(
        cert,
        issuer_cert
    )

    current = now_utc()

    try:
        valid_time = (
            cert.not_valid_before_utc
            <= current
            <= cert.not_valid_after_utc
        )
    except AttributeError:

        valid_time = (
            cert.not_valid_before
            <= current.replace(tzinfo=None)
            <= cert.not_valid_after
        )

    issuer_ok = (
        cert.issuer == issuer_cert.subject
    )

    revocation_ok = (
        cert.serial_number not in revoked
    )

    trusted = (
        signature_ok
        and valid_time
        and issuer_ok
        and revocation_ok
    )

    return {
        "Signature": signature_ok,
        "Validity": valid_time,
        "Issuer": issuer_ok,
        "Revocation": revocation_ok,
        "Trusted": trusted
    }


# ============================================================
# APPLICATION HEADER
# ============================================================

st.title(
    "🔐 TrustChain — Real-Time PKI Laboratory"
)

st.markdown(
    """
    **Interactive Public Key Infrastructure Laboratory**

    Explore certificate authorities, X.509 certificates,
    digital signatures, trust chains and certificate revocation.
    """
)

st.divider()


# ============================================================
# TABS
# ============================================================

dashboard, ca_tab, explorer, signature_tab, revocation, secure = st.tabs(
    [
        "📊 Dashboard",
        "🏛️ Certificate Authority",
        "📜 Certificate Explorer",
        "✍️ Digital Signature",
        "🚫 Revocation",
        "🔒 Secure Communication"
    ]
)


# ============================================================
# DASHBOARD
# ============================================================

with dashboard:

    st.header("PKI Dashboard")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Root CA",
        "ACTIVE"
        if st.session_state.root_cert
        else "NOT CREATED"
    )

    col2.metric(
        "Intermediate CA",
        "ACTIVE"
        if st.session_state.intermediate_cert
        else "NOT CREATED"
    )

    col3.metric(
        "Certificates",
        len(st.session_state.certificates)
    )

    col4.metric(
        "Revoked",
        len(st.session_state.revoked)
    )

    st.divider()

    st.subheader("PKI Trust Chain")

    st.code(
        """
                 ROOT CA
                    │
                    │ signs
                    ▼
            INTERMEDIATE CA
                    │
             ┌──────┴──────┐
             │             │
             ▼             ▼
          USER          SERVER
       CERTIFICATE    CERTIFICATE
             │
             ▼
       DIGITAL SIGNATURE
             │
             ▼
       VERIFICATION
             │
       ┌─────┴─────┐
       ▼           ▼
     TRUSTED    REJECTED
        """
    )

    st.subheader("Implemented PKI Components")

    components = [
        "✓ RSA Asymmetric Cryptography",
        "✓ ECC Cryptography",
        "✓ X.509 Certificates",
        "✓ Root Certificate Authority",
        "✓ Intermediate Certificate Authority",
        "✓ Certificate Chain",
        "✓ Digital Signatures",
        "✓ SHA-256",
        "✓ Certificate Revocation",
        "✓ Secure Communication"
    ]

    for component in components:
        st.write(component)


# ============================================================
# CERTIFICATE AUTHORITY
# ============================================================

with ca_tab:

    st.header("🏛️ Certificate Authority")

    # --------------------------------------------------------
    # ROOT CA
    # --------------------------------------------------------

    st.subheader("1. Generate Root CA")

    root_name = st.text_input(
        "Root CA Name",
        "TrustChain Root CA"
    )

    root_algorithm = st.selectbox(
        "Root CA Algorithm",
        ["RSA", "ECC"],
        key="root_algo"
    )

    if st.button(
        "Generate Root CA",
        type="primary"
    ):

        key, cert = create_root_ca(
            root_name,
            root_algorithm
        )

        st.session_state.root_key = key
        st.session_state.root_cert = cert

        st.success(
            "✓ Root CA created successfully."
        )

    if st.session_state.root_cert:

        cert = st.session_state.root_cert

        st.success("Root CA ACTIVE")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Algorithm",
            algorithm_name(
                st.session_state.root_key
            )
        )

        col2.metric(
            "Type",
            "Root CA"
        )

        col3.metric(
            "Validity",
            "10 Years"
        )

        st.write(
            "**Fingerprint:**",
            fingerprint(cert)
        )

        with st.expander(
            "View Root CA Certificate"
        ):

            st.code(
                certificate_pem(cert),
                language="text"
            )

    st.divider()

    # --------------------------------------------------------
    # INTERMEDIATE CA
    # --------------------------------------------------------

    st.subheader("2. Generate Intermediate CA")

    if not st.session_state.root_cert:

        st.warning(
            "Generate the Root CA first."
        )

    else:

        intermediate_name = st.text_input(
            "Intermediate CA Name",
            "TrustChain Intermediate CA"
        )

        intermediate_algorithm = st.selectbox(
            "Intermediate CA Algorithm",
            ["RSA", "ECC"],
            key="intermediate_algo"
        )

        if st.button(
            "Generate Intermediate CA"
        ):

            key, cert = create_intermediate_ca(
                st.session_state.root_key,
                st.session_state.root_cert,
                intermediate_name,
                intermediate_algorithm
            )

            st.session_state.intermediate_key = key
            st.session_state.intermediate_cert = cert

            st.success(
                "✓ Intermediate CA created and signed by Root CA."
            )

    if st.session_state.intermediate_cert:

        cert = st.session_state.intermediate_cert

        st.success(
            "Intermediate CA ACTIVE"
        )

        st.write(
            "**Issuer:**",
            cert.issuer.rfc4514_string()
        )

        st.write(
            "**Subject:**",
            cert.subject.rfc4514_string()
        )

        st.write(
            "**Algorithm:**",
            algorithm_name(
                st.session_state.intermediate_key
            )
        )

        st.write(
            "**Fingerprint:**",
            fingerprint(cert)
        )

    st.divider()

    # --------------------------------------------------------
    # USER CERTIFICATE
    # --------------------------------------------------------

    st.subheader("3. Issue End-Entity Certificate")

    if not st.session_state.intermediate_cert:

        st.warning(
            "Generate the Intermediate CA first."
        )

    else:

        user_name = st.text_input(
            "Certificate Common Name",
            "student.trustchain.local"
        )

        user_algorithm = st.selectbox(
            "Certificate Algorithm",
            ["RSA", "ECC"],
            key="user_algo"
        )

        if st.button(
            "Issue Certificate",
            type="primary"
        ):

            key, cert = create_user_certificate(
                st.session_state.intermediate_key,
                st.session_state.intermediate_cert,
                user_name,
                user_algorithm
            )

            st.session_state.certificates[
                user_name
            ] = {
                "key": key,
                "cert": cert
            }

            st.success(
                "✓ End-entity certificate issued."
            )

        if st.session_state.certificates:

            st.subheader(
                "Issued Certificates"
            )

            for name, item in st.session_state.certificates.items():

                cert = item["cert"]

                status = (
                    "REVOKED"
                    if cert.serial_number
                    in st.session_state.revoked
                    else "ACTIVE"
                )

                st.write(
                    f"**{name}** — "
                    f"{algorithm_name(item['key'])} — "
                    f"{status}"
                )


# ============================================================
# CERTIFICATE EXPLORER
# ============================================================

with explorer:

    st.header(
        "📜 X.509 Certificate Explorer"
    )

    if not st.session_state.certificates:

        st.info(
            "Issue an end-entity certificate first."
        )

    else:

        names = list(
            st.session_state.certificates.keys()
        )

        selected = st.selectbox(
            "Select Certificate",
            names,
            key="explorer_cert"
        )

        item = (
            st.session_state.certificates[
                selected
            ]
        )

        cert = item["cert"]

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**Subject**"
            )

            st.code(
                cert.subject.rfc4514_string()
            )

            st.write(
                "**Issuer**"
            )

            st.code(
                cert.issuer.rfc4514_string()
            )

            st.write(
                "**Serial Number**"
            )

            st.code(
                str(cert.serial_number)
            )

        with col2:

            st.write(
                "**Algorithm**"
            )

            st.code(
                algorithm_name(item["key"])
            )

            st.write(
                "**Signature Algorithm**"
            )

            st.code(
                cert.signature_algorithm_oid._name
            )

            st.write(
                "**SHA-256 Fingerprint**"
            )

            st.code(
                fingerprint(cert)
            )

        st.divider()

        st.subheader(
            "Certificate Validity"
        )

        try:

            valid_from = (
                cert.not_valid_before_utc
            )

            valid_until = (
                cert.not_valid_after_utc
            )

        except AttributeError:

            valid_from = (
                cert.not_valid_before
            )

            valid_until = (
                cert.not_valid_after
            )

        st.write(
            "Valid From:",
            valid_from
        )

        st.write(
            "Valid Until:",
            valid_until
        )

        st.divider()

        st.subheader(
            "Trust Validation"
        )

        checks = check_certificate(
            cert,
            st.session_state.intermediate_cert,
            st.session_state.revoked
        )

        for name, result in checks.items():

            if result:

                st.success(
                    "✓ " + name + ": PASS"
                )

            else:

                st.error(
                    "✗ " + name + ": FAIL"
                )

        if checks["Trusted"]:

            st.success(
                "🔐 FINAL RESULT: CERTIFICATE TRUSTED"
            )

        else:

            st.error(
                "🚨 FINAL RESULT: CERTIFICATE NOT TRUSTED"
            )

        st.divider()

        st.subheader(
            "PEM Certificate"
        )

        st.code(
            certificate_pem(cert),
            language="text"
        )


# ============================================================
# DIGITAL SIGNATURE
# ============================================================

with signature_tab:

    st.header(
        "✍️ Digital Signature Laboratory"
    )

    if not st.session_state.certificates:

        st.warning(
            "Create a certificate first."
        )

    else:

        names = list(
            st.session_state.certificates.keys()
        )

        signer = st.selectbox(
            "Signing Certificate",
            names,
            key="signature_cert"
        )

        item = (
            st.session_state.certificates[
                signer
            ]
        )

        message = st.text_area(
            "Message",
            "I authorize this secure transaction."
        )

        if st.button(
            "Generate Digital Signature",
            type="primary"
        ):

            signature = sign_data(
                item["key"],
                message.encode("utf-8")
            )

            st.session_state.signature = signature

            st.session_state.signed_message = message

            st.success(
                "✓ Digital signature generated."
            )

        if st.session_state.signature:

            st.subheader(
                "Generated Signature"
            )

            st.code(
                st.session_state.signature.hex()
            )

            st.write(
                "Signature size:",
                len(
                    st.session_state.signature
                ),
                "bytes"
            )

            st.divider()

            st.subheader(
                "Verify Signature"
            )

            verification_message = st.text_area(
                "Message to Verify",
                st.session_state.signed_message,
                key="verify_message"
            )

            if st.button(
                "Verify Signature"
            ):

                result = verify_data(
                    item["key"].public_key(),
                    verification_message.encode("utf-8"),
                    st.session_state.signature
                )

                if result:

                    st.success(
                        "✓ SIGNATURE VALID"
                    )

                else:

                    st.error(
                        "✗ SIGNATURE INVALID"
                    )

            st.info(
                "Try changing ₹5000 to ₹9000 or modify one character. "
                "The signature verification will fail."
            )


# ============================================================
# REVOCATION
# ============================================================

with revocation:

    st.header(
        "🚫 Certificate Revocation Center"
    )

    if not st.session_state.certificates:

        st.info(
            "No certificates available."
        )

    else:

        names = list(
            st.session_state.certificates.keys()
        )

        selected = st.selectbox(
            "Certificate",
            names,
            key="revocation_cert"
        )

        item = (
            st.session_state.certificates[
                selected
            ]
        )

        cert = item["cert"]

        revoked = (
            cert.serial_number
            in st.session_state.revoked
        )

        if revoked:

            st.error(
                "🚨 CERTIFICATE REVOKED"
            )

            if st.button(
                "Restore Certificate"
            ):

                st.session_state.revoked.remove(
                    cert.serial_number
                )

                st.rerun()

        else:

            st.success(
                "✓ CERTIFICATE ACTIVE"
            )

            if st.button(
                "Revoke Certificate",
                type="primary"
            ):

                st.session_state.revoked.add(
                    cert.serial_number
                )

                st.rerun()

        st.divider()

        st.subheader(
            "Certificate Lifecycle"
        )

        st.code(
            """
        KEY GENERATION
              |
              v
        CERTIFICATE ISSUANCE
              |
              v
            ACTIVE
              |
       +------+------+
       |             |
       v             v
    EXPIRED       REVOKED
       |             |
       +------+------+
              |
              v
          UNTRUSTED
            """
        )


# ============================================================
# SECURE COMMUNICATION
# ============================================================

with secure:

    st.header(
        "🔒 Secure Communication Simulator"
    )

    if not st.session_state.certificates:

        st.warning(
            "Create a certificate first."
        )

    else:

        names = list(
            st.session_state.certificates.keys()
        )

        sender = st.selectbox(
            "Sender Certificate",
            names,
            key="secure_sender"
        )

        item = (
            st.session_state.certificates[
                sender
            ]
        )

        message = st.text_area(
            "Secure Message",
            "Transfer request: Rs. 5000"
        )

        if st.button(
            "Send Secure Message",
            type="primary"
        ):

            cert = item["cert"]

            checks = check_certificate(
                cert,
                st.session_state.intermediate_cert,
                st.session_state.revoked
            )

            certificate_ok = (
                checks["Trusted"]
            )

            signature = sign_data(
                item["key"],
                message.encode("utf-8")
            )

            signature_ok = verify_data(
                item["key"].public_key(),
                message.encode("utf-8"),
                signature
            )

            message_hash = hashlib.sha256(
                message.encode("utf-8")
            ).hexdigest()

            st.subheader(
                "Security Pipeline"
            )

            st.write(
                "1️⃣ Certificate Authentication"
            )

            if certificate_ok:

                st.success(
                    "✓ Certificate trusted"
                )

            else:

                st.error(
                    "✗ Certificate rejected"
                )

            st.write(
                "2️⃣ Digital Signature"
            )

            if signature_ok:

                st.success(
                    "✓ Signature verified"
                )

            else:

                st.error(
                    "✗ Signature verification failed"
                )

            st.write(
                "3️⃣ Message Integrity"
            )

            st.code(
                message_hash
            )

            if (
                certificate_ok
                and signature_ok
            ):

                st.success(
                    "🔐 SECURE COMMUNICATION ESTABLISHED"
                )

            else:

                st.error(
                    "🚨 SECURE COMMUNICATION BLOCKED"
                )

            st.divider()

            st.subheader(
                "Communication Flow"
            )

            st.code(
                """
                 SENDER
                    |
                    | X.509 Certificate
                    v
             Certificate Check
                    |
             +------+------+
             |             |
             v             v
          Trusted       Rejected
             |
             v
       Digital Signature
             |
             v
       Message Integrity
             |
             v
           RECEIVER
                """
            )
