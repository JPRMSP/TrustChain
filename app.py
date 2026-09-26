import streamlit as st
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta, timezone
import hashlib
import pandas as pd


# ============================================================
# TRUSTCHAIN - PKI LAB
# ============================================================

st.set_page_config(
    page_title="TrustChain PKI Lab",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# SESSION STATE
# ============================================================

if "root_key" not in st.session_state:
    st.session_state.root_key = None

if "root_cert" not in st.session_state:
    st.session_state.root_cert = None

if "intermediate_key" not in st.session_state:
    st.session_state.intermediate_key = None

if "intermediate_cert" not in st.session_state:
    st.session_state.intermediate_cert = None

if "certificates" not in st.session_state:
    st.session_state.certificates = {}

if "revoked" not in st.session_state:
    st.session_state.revoked = set()

if "signature" not in st.session_state:
    st.session_state.signature = None

if "signed_message" not in st.session_state:
    st.session_state.signed_message = ""


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc)


def generate_key(algorithm="RSA"):
    if algorithm == "ECC":
        return ec.generate_private_key(ec.SECP256R1())

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def key_algorithm(key):
    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA-2048"

    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ECC-{key.curve.name}"

    return "Unknown"


def serialize_private_key(key):
    return key.private_bytes(
        Encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


def serialize_certificate(cert):
    return cert.public_bytes(
        serialization.Encoding.PEM
    ).decode()


def fingerprint(cert):
    return cert.fingerprint(
        hashes.SHA256()
    ).hex(":").upper()


def create_name(
    common_name,
    organization="TrustChain PKI Lab"
):
    return x509.Name([
        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            "IN"
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            organization
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            common_name
        )
    ])


# ============================================================
# DIGITAL SIGNATURE FUNCTIONS
# ============================================================

def sign_data(private_key, data):

    if isinstance(
        private_key,
        rsa.RSAPrivateKey
    ):
        return private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )


def verify_data(
    public_key,
    data,
    signature
):

    try:

        if isinstance(
            public_key,
            rsa.RSAPublicKey
        ):

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

    except InvalidSignature:

        return False

    except Exception:

        return False


# ============================================================
# ROOT CA
# ============================================================

def create_root_ca(
    common_name,
    algorithm
):

    key = generate_key(algorithm)

    name = create_name(common_name)

    now = utc_now()

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - timedelta(minutes=1)
        )
        .not_valid_after(
            now + timedelta(days=3650)
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

    return key, certificate


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

    subject = create_name(common_name)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            utc_now() - timedelta(minutes=1)
        )
        .not_valid_after(
            utc_now() + timedelta(days=1825)
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

    return key, certificate


# ============================================================
# END ENTITY CERTIFICATE
# ============================================================

def issue_certificate(
    issuer_key,
    issuer_cert,
    common_name,
    algorithm
):

    key = generate_key(algorithm)

    subject = create_name(common_name)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            utc_now() - timedelta(minutes=1)
        )
        .not_valid_after(
            utc_now() + timedelta(days=365)
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

    return key, certificate


# ============================================================
# CERTIFICATE VERIFICATION
# ============================================================

def verify_certificate_signature(
    certificate,
    issuer_certificate
):

    try:

        issuer_public_key = (
            issuer_certificate.public_key()
        )

        if isinstance(
            issuer_public_key,
            rsa.RSAPublicKey
        ):

            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )

        else:

            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(
                    certificate.signature_hash_algorithm
                )
            )

        return True

    except Exception:

        return False


def certificate_status(
    certificate,
    issuer_certificate,
    revoked
):

    checks = {}

    checks["Signature"] = (
        verify_certificate_signature(
            certificate,
            issuer_certificate
        )
    )

    now = utc_now()

    checks["Validity"] = (
        certificate.not_valid_before_utc
        <= now
        <= certificate.not_valid_after_utc
    )

    checks["Revocation"] = (
        certificate.serial_number
        not in revoked
    )

    checks["Issuer"] = (
        certificate.issuer
        == issuer_certificate.subject
    )

    checks["Trusted"] = all(
        checks.values()
    )

    return checks


# ============================================================
# APPLICATION HEADER
# ============================================================

st.title(
    "🔐 TrustChain — Live PKI Laboratory"
)

st.markdown(
    """
    A real-time Public Key Infrastructure laboratory
    demonstrating:

    **Certificate Authority → X.509 Certificate →
    Trust Chain → Digital Signature → Verification →
    Revocation**
    """
)

st.divider()


# ============================================================
# TABS
# ============================================================

tabs = st.tabs([
    "📊 Dashboard",
    "🏛️ Certificate Authority",
    "📜 Certificate Explorer",
    "✍️ Digital Signature",
    "🚫 Revocation Center",
    "🔒 Secure Communication"
])


# ============================================================
# DASHBOARD
# ============================================================

with tabs[0]:

    st.header(
        "PKI Trust Dashboard"
    )

    root_exists = (
        st.session_state.root_cert
        is not None
    )

    intermediate_exists = (
        st.session_state.intermediate_cert
        is not None
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Root CA",
        "ACTIVE"
        if root_exists
        else "NOT CREATED"
    )

    col2.metric(
        "Intermediate CA",
        "ACTIVE"
        if intermediate_exists
        else "NOT CREATED"
    )

    col3.metric(
        "Certificates",
        len(
            st.session_state.certificates
        )
    )

    col4.metric(
        "Revoked",
        len(
            st.session_state.revoked
        )
    )

    st.divider()

    st.subheader(
        "Trust Architecture"
    )

    if root_exists:

        st.success(
            "✓ Root CA is available"
        )

        st.code(
            """
                    ┌──────────────────────┐
                    │       ROOT CA        │
                    │   TrustChain Root    │
                    └──────────┬───────────┘
                               │
                               │ signs
                               ▼
                    ┌──────────────────────┐
                    │   INTERMEDIATE CA    │
                    │    TrustChain ICA    │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
              ┌───────────┐        ┌────────────┐
              │   USER    │        │   SERVER   │
              │Certificate│        │Certificate │
              └───────────┘        └────────────┘
            """
        )

    else:

        st.warning(
            "Create a Root CA from the Certificate Authority tab."
        )

    st.subheader(
        "PKI Concepts Demonstrated"
    )

    concepts = pd.DataFrame({

        "Concept": [

            "Asymmetric Cryptography",
            "X.509 Certificates",
            "Certificate Authority",
            "Certificate Chain",
            "Digital Signature",
            "Certificate Revocation",
            "Key Lifecycle",
            "Trust Model"

        ],

        "Status": [

            "Implemented",
            "Implemented",
            "Implemented",
            "Implemented",
            "Implemented",
            "Implemented",
            "Implemented"

        ]

    })

    st.dataframe(
        concepts,
        use_container_width=True
    )


# ============================================================
# CERTIFICATE AUTHORITY
# ============================================================

with tabs[1]:

    st.header(
        "🏛️ Certificate Authority"
    )

    st.subheader(
        "Step 1 — Create Root CA"
    )

    root_cn = st.text_input(
        "Root CA Common Name",
        value="TrustChain Root CA"
    )

    root_algorithm = st.selectbox(
        "Root CA Algorithm",
        ["RSA", "ECC"],
        key="root_algorithm"
    )

    if st.button(
        "Generate Root CA",
        type="primary"
    ):

        with st.spinner(
            "Generating cryptographic keys and certificate..."
        ):

            key, certificate = (
                create_root_ca(
                    root_cn,
                    root_algorithm
                )
            )

            st.session_state.root_key = key
            st.session_state.root_cert = certificate

        st.success(
            "✓ Root CA generated successfully."
        )

    if st.session_state.root_cert:

        certificate = (
            st.session_state.root_cert
        )

        st.markdown(
            "### Root CA Information"
        )

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Algorithm",
            key_algorithm(
                st.session_state.root_key
            )
        )

        c2.metric(
            "Certificate",
            "X.509"
        )

        c3.metric(
            "Validity",
            "10 Years"
        )

        st.code(
            serialize_certificate(
                certificate
            ),
            language="text"
        )

        st.write(
            "**SHA-256 Fingerprint:**",
            fingerprint(certificate)
        )

    st.divider()

    st.subheader(
        "Step 2 — Create Intermediate CA"
    )

    if not st.session_state.root_cert:

        st.warning(
            "Create the Root CA first."
        )

    else:

        intermediate_cn = st.text_input(
            "Intermediate CA Common Name",
            value="TrustChain Intermediate CA"
        )

        intermediate_algorithm = st.selectbox(
            "Intermediate Algorithm",
            ["RSA", "ECC"],
            key="intermediate_algorithm"
        )

        if st.button(
            "Generate Intermediate CA"
        ):

            key, certificate = (
                create_intermediate_ca(
                    st.session_state.root_key,
                    st.session_state.root_cert,
                    intermediate_cn,
                    intermediate_algorithm
                )
            )

            st.session_state.intermediate_key = key
            st.session_state.intermediate_cert = certificate

            st.success(
                "✓ Intermediate CA signed by Root CA."
            )

    if st.session_state.intermediate_cert:

        certificate = (
            st.session_state.intermediate_cert
        )

        st.markdown(
            "### Intermediate CA Certificate"
        )

        st.write(
            "**Issuer:**",
            certificate.issuer.rfc4514_string()
        )

        st.write(
            "**Subject:**",
            certificate.subject.rfc4514_string()
        )

        st.write(
            "**Fingerprint:**",
            fingerprint(certificate)
        )

        st.code(
            serialize_certificate(
                certificate
            ),
            language="text"
        )

    st.divider()

    st.subheader(
        "Step 3 — Issue End-Entity Certificate"
    )

    if not st.session_state.intermediate_cert:

        st.warning(
            "Create an Intermediate CA first."
        )

    else:

        entity_cn = st.text_input(
            "Certificate Common Name",
            value="student.trustchain.local"
        )

        entity_algorithm = st.selectbox(
            "End-Entity Algorithm",
            ["RSA", "ECC"],
            key="entity_algorithm"
        )

        if st.button(
            "Issue Certificate",
            type="primary"
        ):

            key, certificate = (
                issue_certificate(
                    st.session_state.intermediate_key,
                    st.session_state.intermediate_cert,
                    entity_cn,
                    entity_algorithm
                )
            )

            st.session_state.certificates[
                entity_cn
            ] = {

                "key": key,
                "cert": certificate

            }

            st.success(
                f"✓ Certificate issued for {entity_cn}"
            )

        if st.session_state.certificates:

            rows = []

            for name, item in (
                st.session_state.certificates.items()
            ):

                certificate = item["cert"]

                rows.append({

                    "Subject": name,

                    "Algorithm":
                        key_algorithm(
                            item["key"]
                        ),

                    "Serial":
                        str(
                            certificate.serial_number
                        ),

                    "Status":
                        (
                            "REVOKED"
                            if certificate.serial_number
                            in st.session_state.revoked
                            else "VALID"
                        )

                })

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True
            )


# ============================================================
# CERTIFICATE EXPLORER
# ============================================================

with tabs[2]:

    st.header(
        "📜 X.509 Certificate Explorer"
    )

    if not st.session_state.certificates:

        st.info(
            "Issue at least one certificate from the Certificate Authority tab."
        )

    else:

        names = list(
            st.session_state.certificates.keys()
        )

        selected = st.selectbox(
            "Select Certificate",
            names
        )

        item = (
            st.session_state.certificates[
                selected
            ]
        )

        certificate = item["cert"]

        st.subheader(
            "Certificate Details"
        )

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**Subject**",
                certificate.subject.rfc4514_string()
            )

            st.write(
                "**Issuer**",
                certificate.issuer.rfc4514_string()
            )

            st.write(
                "**Serial Number**",
                certificate.serial_number
            )

            st.write(
                "**Signature Algorithm**",
                certificate.signature_algorithm_oid._name
            )

        with col2:

            st.write(
                "**Valid From**",
                certificate.not_valid_before_utc
            )

            st.write(
                "**Valid Until**",
                certificate.not_valid_after_utc
            )

            st.write(
                "**Public Key**",
                key_algorithm(
                    item["key"]
                )
            )

            st.write(
                "**SHA-256 Fingerprint**",
                fingerprint(certificate)
            )

        st.divider()

        issuer = (
            st.session_state.intermediate_cert
        )

        checks = certificate_status(
            certificate,
            issuer,
            st.session_state.revoked
        )

        st.subheader(
            "Certificate Validation"
        )

        for check, result in checks.items():

            if result:

                st.success(
                    f"✓ {check}: PASS"
                )

            else:

                st.error(
                    f"✗ {check}: FAIL"
                )

        if checks["Trusted"]:

            st.success(
                "🔐 FINAL RESULT: CERTIFICATE TRUSTED"
            )

        else:

            st.error(
                "🚨 FINAL RESULT: CERTIFICATE NOT TRUSTED"
            )

        st.subheader(
            "PEM Certificate"
        )

        st.code(
            serialize_certificate(
                certificate
            ),
            language="text"
        )


# ============================================================
# DIGITAL SIGNATURE
# ============================================================

with tabs[3]:

    st.header(
        "✍️ Digital Signature Laboratory"
    )

    if not st.session_state.certificates:

        st.warning(
            "Create an end-entity certificate first."
        )

    else:

        selected = st.selectbox(
            "Signing Certificate",
            list(
                st.session_state.certificates.keys()
            ),
            key="signer"
        )

        item = (
            st.session_state.certificates[
                selected
            ]
        )

        message = st.text_area(
            "Message to Sign",
            value=(
                "I authorize this secure transaction "
                "through TrustChain PKI."
            )
        )

        if st.button(
            "Generate Digital Signature",
            type="primary"
        ):

            signature = sign_data(
                item["key"],
                message.encode()
            )

            st.session_state.signature = signature
            st.session_state.signed_message = message

            st.success(
                "✓ Digital signature generated."
            )

        if st.session_state.signature:

            st.subheader(
                "Signature"
            )

            st.code(
                st.session_state.signature.hex()
            )

            st.write(
                "Signature length:",
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
                "Message for Verification",
                value=(
                    st.session_state.signed_message
                ),
                key="verification_message"
            )

            if st.button(
                "Verify Digital Signature"
            ):

                valid = verify_data(
                    item["key"].public_key(),
                    verification_message.encode(),
                    st.session_state.signature
                )

                if valid:

                    st.success(
                        "✓ DIGITAL SIGNATURE VALID — "
                        "Message is authentic and unchanged."
                    )

                else:

                    st.error(
                        "✗ DIGITAL SIGNATURE INVALID — "
                        "Message was modified or signature is invalid."
                    )

            st.info(
                "Demo: change even one character in the message and verify again."
            )


# ============================================================
# REVOCATION CENTER
# ============================================================

with tabs[4]:

    st.header(
        "🚫 Certificate Revocation Center"
    )

    if not st.session_state.certificates:

        st.info(
            "No certificates have been issued."
        )

    else:

        certificate_names = list(
            st.session_state.certificates.keys()
        )

        selected = st.selectbox(
            "Select certificate",
            certificate_names,
            key="revoke_certificate"
        )

        item = (
            st.session_state.certificates[
                selected
            ]
        )

        certificate = item["cert"]

        if (
            certificate.serial_number
            in st.session_state.revoked
        ):

            st.error(
                "Certificate is currently REVOKED."
            )

            if st.button(
                "Restore Certificate For Demo"
            ):

                st.session_state.revoked.remove(
                    certificate.serial_number
                )

                st.success(
                    "Certificate restored for demonstration."
                )

                st.rerun()

        else:

            st.success(
                "Certificate is currently ACTIVE."
            )

            if st.button(
                "Revoke Certificate",
                type="primary"
            ):

                st.session_state.revoked.add(
                    certificate.serial_number
                )

                st.error(
                    "Certificate has been revoked."
                )

                st.rerun()

        st.divider()

        st.subheader(
            "Certificate Status"
        )

        st.write(
            "**Subject:**",
            certificate.subject.rfc4514_string()
        )

        st.write(
            "**Serial:**",
            certificate.serial_number
        )

        st.write(
            "**SHA-256:**",
            fingerprint(certificate)
        )

        st.write(
            "**Status:**",
            (
                "REVOKED"
                if certificate.serial_number
                in st.session_state.revoked
                else "ACTIVE"
            )
        )

        st.divider()

        st.subheader(
            "Live PKI Lifecycle"
        )

        st.code(
            """
        KEY GENERATION
              │
              ▼
        CERTIFICATE ISSUANCE
              │
              ▼
            ACTIVE
              │
              ├───────────────┐
              │               │
              ▼               ▼
          EXPIRED          REVOKED
              │               │
              └───────┬───────┘
                      ▼
                  UNTRUSTED
            """
        )


# ============================================================
# SECURE COMMUNICATION
# ============================================================

with tabs[5]:

    st.header(
        "🔒 Secure Communication Simulator"
    )

    st.markdown(
        """
        This demonstration combines certificate authentication,
        digital signatures and message integrity.
        """
    )

    if not st.session_state.certificates:

        st.warning(
            "Create a certificate before running the simulation."
        )

    else:

        selected = st.selectbox(
            "Select Sender",
            list(
                st.session_state.certificates.keys()
            ),
            key="sender"
        )

        item = (
            st.session_state.certificates[
                selected
            ]
        )

        secure_message = st.text_area(
            "Secure Message",
            value="Transfer request: ₹5000"
        )

        if st.button(
            "Send Secure Message",
            type="primary"
        ):

            certificate = item["cert"]

            certificate_ok = False

            if (
                st.session_state.intermediate_cert
            ):

                checks = certificate_status(
                    certificate,
                    st.session_state.intermediate_cert,
                    st.session_state.revoked
                )

                certificate_ok = (
                    checks["Trusted"]
                )

            signature = sign_data(
                item["key"],
                secure_message.encode()
            )

            signature_ok = verify_data(
                item["key"].public_key(),
                secure_message.encode(),
                signature
            )

            st.subheader(
                "Security Pipeline"
            )

            st.write(
                "1️⃣ Sender Certificate"
            )

            if certificate_ok:

                st.success(
                    "✓ Certificate trusted"
                )

            else:

                st.error(
                    "✗ Certificate not trusted"
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

            message_hash = hashlib.sha256(
                secure_message.encode()
            ).hexdigest()

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
                "What happened?"
            )

            st.markdown(
                """
                ```text
                Sender
                   │
                   ├── X.509 Certificate
                   │
                   ▼
                Certificate Validation
                   │
                   ├── Issuer
                   ├── Signature
                   ├── Validity
                   └── Revocation
                   │
                   ▼
                Digital Signature
                   │
                   ▼
                Message Integrity
                   │
                   ▼
                Receiver
                ```
                """
            )
