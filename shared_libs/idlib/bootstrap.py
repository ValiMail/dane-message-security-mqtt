"""All the logic for identity bootstrapping is here."""
import datetime
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import dns

from dane_discovery.dane import DANE
from dane_discovery.exceptions import TLSAError


class Bootstrap:
    """This class holds the logic for bootstrapping the device identity.

    This part of the application supports the creation of a CSR for use with
    an external CA, or the creation of a self-signed certificate. This does
    not support the creation of a local CA.
    """

    pki_assets = {"key": {"file": "{}.key.pem",
                          "mode": 0o600},
                  "cert": {"file": "{}.crt.pem",
                           "mode": 0o600},
                  "csr": {"file": "{}.csr.pem",
                          "mode": 0o600}}

    def __init__(self, identity_name, identity_path, app_userid, **kwargs):
        """Initialize the identity bootstrapper.

        Args:
            identity_name (str): DNS name for identity.
            crypto_path (str): Path where crypto assets should be stored.
            app_userid (str): "UserID for application user. Used for setting
                file permissions."

        Keyword args:
            state (str): State for CSR.
            country (str):
            locality (str):
            organization (str):
        """
        self.valid_kwargs = ["state", "country", "locality", "organization"]
        self.identity_path = identity_path
        self.state = "CA"
        self.country = "US"
        self.locality = "San Francisco"
        self.organization = "example"
        self.identity_name = identity_name
        self.app_userid = int(app_userid)
        self.set_attributes_from_kwargs(kwargs)

    def set_attributes_from_kwargs(self, kwargs):
        """Set instance attributes from kwargs."""
        for val in self.valid_kwargs:
            if val in kwargs:
                setattr(self, val, kwargs[val])

    def generate_private_key(self):
        """Create private key."""
        key = rsa.generate_private_key(public_exponent=65537,
                                       key_size=2048,
                                       backend=default_backend())
        asset = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,  # NOQA
                                  serialization.NoEncryption())
        self.write_pki_asset(asset, "key")

    def build_x509_name(self):
        """Return an x509.Name object, built using instantiation vars."""
        return x509.Name(
                  [x509.NameAttribute(NameOID.COUNTRY_NAME,
                                      self.country),
                   x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                                      self.state),
                   x509.NameAttribute(NameOID.LOCALITY_NAME,
                                      self.locality),
                   x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                      self.organization),
                   x509.NameAttribute(NameOID.COMMON_NAME,
                                      self.identity_name)])

    def build_subject_alt_name(self):
        """Return x509 SAN extension."""
        return x509.SubjectAlternativeName([x509.DNSName(self.identity_name)])

    def generate_csr(self):
        """Generate a Certificate Signing Request (CSR)."""
        csr = x509.CertificateSigningRequestBuilder()
        csr = csr.subject_name(self.build_x509_name())
        csr = csr.add_extension(x509.SubjectAlternativeName(
                                   [x509.DNSName(self.identity_name)]),
                                critical=False)
        private_key_path = self.get_pki_asset("key")
        pri_key = serialization.load_pem_private_key(private_key_path,
                                                     password=None,
                                                     backend=default_backend())
        csr = csr.sign(pri_key, hashes.SHA256(), default_backend())
        asset = csr.public_bytes(serialization.Encoding.PEM)
        self.write_pki_asset(asset, "csr")

    def generate_selfsigned_certificate(self):
        """Generate a self-signed certificate, write to disk."""
        key = self.get_private_key_obj()
        issuer = subject = self.build_x509_name()
        subject_alt_name = self.build_subject_alt_name()
        cert = x509.CertificateBuilder(
        ).subject_name(subject
        ).issuer_name(issuer
        ).public_key(key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(datetime.datetime.utcnow() +
                          datetime.timedelta(days=10)
        ).add_extension(subject_alt_name, critical=False,
        ).sign(key, hashes.SHA256())
        self.write_pki_asset(cert.public_bytes(serialization.Encoding.PEM), 
                             "cert")

    def public_identity_is_valid(self):
        """Return True if public certificate corresponds to private key."""
        id_name = self.identity_name
        try:
            dns_tlsa_rr = DANE.get_first_leaf_certificate(id_name)
        except (dns.resolver.NoAnswer, TLSAError):
            print("No such record in DNS!")
            return False
        if dns_tlsa_rr is None:
            print("No TLSA entity record found for {}".format(id_name))
            return False
        entity_cert = dns_tlsa_rr["certificate_association"]
        dns_cert_obj = DANE.build_x509_object(entity_cert)
        return self.cert_matches_private_key(dns_cert_obj)

    def get_private_key_obj(self):
        """Return the private key object."""
        key_pem = self.get_pki_asset("key")
        key = serialization.load_pem_private_key(key_pem, password=None,
                                                 backend=default_backend())
        return key

    def get_local_cert_obj(self):
        """Return the local certificate object."""
        cert_pem = self.get_pki_asset("cert")
        cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())  # NOQA
        return cert

    def get_pki_asset(self, asset_type):
        """Return the contents of a PKI asset file."""
        asset_path = self.get_path_for_pki_asset(asset_type)
        print("Reading {}".format(asset_path))
        with open(asset_path, "rb") as f_obj:
            return f_obj.read()

    def write_pki_asset(self, asset, asset_type):
        """Write PKI asset to file, set permissions."""
        asset_path = self.get_path_for_pki_asset(asset_type)
        asset_mode = self.pki_assets[asset_type]["mode"]
        with open(asset_path, "wb") as f_obj:
            f_obj.write(asset)
        print("Wrote {}".format(asset_path))
        os.chown(asset_path, self.app_userid, -1)
        os.chmod(asset_path, asset_mode)

    def get_path_for_pki_asset(self, asset_type):
        """Return path for private key."""
        asset_types = {"cert": self.pki_assets["cert"], 
                       "key": self.pki_assets["key"],
                       "csr": self.pki_assets["csr"]}
        if asset_type not in asset_types:
            raise ValueError
        file_name = asset_types[asset_type]["file"].format(self.identity_name)
        return os.path.join(self.identity_path, file_name)

    def cert_matches_private_key(self, cert_obj):
        """Return True if certificate matches private key, else False."""
        test_text = "test_text".encode()
        public = cert_obj.public_key()
        private = self.get_private_key_obj()
        sig = private.sign(test_text,
                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                       salt_length=padding.PSS.MAX_LENGTH),
                           hashes.SHA256())
        try:
            public.verify(sig, test_text,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
            return True
        except InvalidSignature:
            pass
        return False

    def render_tlsa_record(self):
        """Return TLSA record value."""
        cert_pem = self.get_pki_asset("cert")
        return DANE.generate_tlsa_record(3, 0, 0, cert_pem)
