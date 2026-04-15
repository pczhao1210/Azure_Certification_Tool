import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from acme import challenges, client, errors, messages
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.mgmt.dns import DnsManagementClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import josepy as jose


logger = logging.getLogger(__name__)

ISRG_ROOT_X1 = """-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbTANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----"""


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value else default


@dataclass
class RenewalSettings:
    acme_email: str
    acme_domains: list[str]
    acme_directory_url: str
    key_vault_url: str
    certificate_name: str
    dns_subscription_id: str
    dns_resource_group: str
    dns_zone_name: str
    dns_challenge_zone_name: str | None
    dns_challenge_resource_group: str | None
    renewal_days_before_expiry: int
    save_local_certs: bool
    cert_output_dir: str
    pfx_password: str | None
    acme_validation_timeout: int
    dns_propagation_timeout: int
    dns_propagation_interval: int
    dns_propagation_stable_seconds: int
    public_dns_servers: list[str]


def load_settings() -> RenewalSettings:
    required = {
        "ACME_EMAIL": os.getenv("ACME_EMAIL"),
        "ACME_DOMAINS": os.getenv("ACME_DOMAINS"),
        "AZURE_KEY_VAULT_URL": os.getenv("AZURE_KEY_VAULT_URL"),
        "AZURE_CERTIFICATE_NAME": os.getenv("AZURE_CERTIFICATE_NAME"),
        "DNS_SUBSCRIPTION_ID": os.getenv("DNS_SUBSCRIPTION_ID"),
        "DNS_RESOURCE_GROUP": os.getenv("DNS_RESOURCE_GROUP"),
        "DNS_ZONE_NAME": os.getenv("DNS_ZONE_NAME"),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

    return RenewalSettings(
        acme_email=required["ACME_EMAIL"] or "",
        acme_domains=_split_csv(required["ACME_DOMAINS"] or ""),
        acme_directory_url=os.getenv("ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),
        key_vault_url=required["AZURE_KEY_VAULT_URL"] or "",
        certificate_name=required["AZURE_CERTIFICATE_NAME"] or "",
        dns_subscription_id=required["DNS_SUBSCRIPTION_ID"] or "",
        dns_resource_group=required["DNS_RESOURCE_GROUP"] or "",
        dns_zone_name=required["DNS_ZONE_NAME"] or "",
        dns_challenge_zone_name=os.getenv("DNS_CHALLENGE_ZONE_NAME"),
        dns_challenge_resource_group=os.getenv("DNS_CHALLENGE_RESOURCE_GROUP"),
        renewal_days_before_expiry=_get_int("RENEWAL_DAYS_BEFORE_EXPIRY", 30),
        save_local_certs=_get_bool("SAVE_LOCAL_CERTS", False),
        cert_output_dir=os.getenv("CERT_OUTPUT_DIR", "/tmp/certificates"),
        pfx_password=os.getenv("PFX_PASSWORD"),
        acme_validation_timeout=_get_int("ACME_VALIDATION_TIMEOUT", 900),
        dns_propagation_timeout=_get_int("DNS_PROPAGATION_TIMEOUT", 900),
        dns_propagation_interval=_get_int("DNS_PROPAGATION_INTERVAL", 15),
        dns_propagation_stable_seconds=_get_int("DNS_PROPAGATION_STABLE_SECONDS", 90),
        public_dns_servers=_split_csv(os.getenv("PUBLIC_DNS_SERVERS", "8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222")),
    )


def _parse_cert_chain(certificate_pem: str) -> list[x509.Certificate]:
    cert_objects: list[x509.Certificate] = []
    cert_blocks = certificate_pem.split("-----END CERTIFICATE-----")
    for block in cert_blocks:
        if "-----BEGIN CERTIFICATE-----" in block:
            cert_pem = block + "-----END CERTIFICATE-----"
            cert_objects.append(x509.load_pem_x509_certificate(cert_pem.encode()))
    if not cert_objects:
        raise ValueError("No valid certificates found")
    return cert_objects


class RenewalManager:
    CHALLENGE_PLACEHOLDER_VALUE = "acme-challenge-placeholder"

    def __init__(self, settings: RenewalSettings):
        self.settings = settings
        self.credential = DefaultAzureCredential()
        self.cert_client = CertificateClient(vault_url=settings.key_vault_url, credential=self.credential)
        self.dns_client = DnsManagementClient(
            credential=self.credential,
            subscription_id=settings.dns_subscription_id,
        )

    def generate_private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def generate_account_key(self):
        return jose.JWKRSA(key=self.generate_private_key())

    def create_csr(self, private_key, domains: list[str]):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=False,
        )
        return builder.sign(private_key, hashes.SHA256())

    def check_certificate_expiry(self, days_before_expiry: int) -> bool:
        try:
            certificate = self.cert_client.get_certificate(self.settings.certificate_name)
            expiry_date = certificate.properties.expires_on
            current_date = datetime.now(expiry_date.tzinfo)
            days_until_expiry = (expiry_date - current_date).days
            logger.info("证书距离过期还有 %s 天 / Certificate expires in %s days", days_until_expiry, days_until_expiry)
            return days_until_expiry <= days_before_expiry
        except ResourceNotFoundError:
            logger.warning("未找到 Key Vault 证书，将创建新证书 / Certificate not found in Key Vault, issuing a new one")
            return True

    def _get_challenge_zone_settings(self):
        return {
            "resource_group": self.settings.dns_challenge_resource_group or self.settings.dns_resource_group,
            "zone_name": self.settings.dns_challenge_zone_name or self.settings.dns_zone_name,
        }

    def _get_relative_record_name(self, fqdn: str, zone_name: str) -> str:
        if fqdn == zone_name:
            return "@"
        suffix = f".{zone_name}"
        if not fqdn.endswith(suffix):
            raise ValueError(
                "DNS_CHALLENGE_ZONE_NAME must match the managed challenge zone. "
                "For delegated challenges, use '_acme-challenge.<domain>' as the zone name."
            )
        return fqdn[: -len(suffix)]

    def _get_managed_record_location(self, record_name: str):
        zone_settings = self._get_challenge_zone_settings()
        relative_name = self._get_relative_record_name(record_name, zone_settings["zone_name"])
        return zone_settings["resource_group"], zone_settings["zone_name"], relative_name

    def _get_existing_txt_values(self, resource_group_name: str, zone_name: str, relative_name: str) -> set[str]:
        try:
            record_set = self.dns_client.record_sets.get(
                resource_group_name=resource_group_name,
                zone_name=zone_name,
                relative_record_set_name=relative_name,
                record_type="TXT",
            )
        except ResourceNotFoundError:
            return set()

        values: set[str] = set()
        for txt_record in record_set.txt_records or []:
            for value in txt_record.value or []:
                if value:
                    values.add(value)
        return values

    def _resolve_txt_values(self, fqdn: str, nameserver: str) -> set[str]:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(fqdn, "TXT")
        values: set[str] = set()
        for rdata in answers:
            for txt_string in rdata.strings:
                values.add(txt_string.decode())
        return values

    def _get_authoritative_nameservers(self, zone_name: str) -> list[str]:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.settings.public_dns_servers
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(zone_name, "NS")
        nameservers: list[str] = []
        for record in answers:
            nameserver = record.to_text().rstrip(".")
            try:
                ns_answers = resolver.resolve(nameserver, "A")
                for ns_record in ns_answers:
                    ns_ip = ns_record.to_text()
                    if ns_ip not in nameservers:
                        nameservers.append(ns_ip)
            except Exception as exc:
                logger.debug("无法解析权威 NS 地址 / Failed to resolve authoritative NS address: %s: %s", nameserver, exc)
        return nameservers

    def _check_dns_visibility(self, fqdn: str, expected_values: set[str], nameservers: list[str]) -> list[dict]:
        results = []
        for nameserver in nameservers:
            try:
                actual_values = self._resolve_txt_values(fqdn, nameserver)
                missing_values = sorted(expected_values - actual_values)
                results.append({"nameserver": nameserver, "ok": not missing_values, "missing": missing_values})
            except Exception as exc:
                results.append({"nameserver": nameserver, "ok": False, "missing": sorted(expected_values), "error": str(exc)})
        return results

    def _wait_for_dns_propagation(self, record_name: str, expected_values: list[str]) -> None:
        authoritative_nameservers = self._get_authoritative_nameservers(self._get_challenge_zone_settings()["zone_name"])
        expected = set(expected_values)
        start = time.time()
        deadline = start + self.settings.dns_propagation_timeout
        last_log_time = start
        stable_since = None

        logger.info("等待 DNS 传播 / Waiting for DNS propagation: %s", record_name)

        while time.time() < deadline:
            authoritative_results = self._check_dns_visibility(record_name, expected, authoritative_nameservers)
            recursive_results = self._check_dns_visibility(record_name, expected, self.settings.public_dns_servers)
            authoritative_ok = all(item["ok"] for item in authoritative_results)
            recursive_ok = all(item["ok"] for item in recursive_results)

            if authoritative_ok and recursive_ok:
                if stable_since is None:
                    stable_since = time.time()
                    logger.info(
                        "DNS 记录已在权威和公共递归 DNS 可见，开始稳定观察 %ss / DNS record visible, starting %ss stability window",
                        self.settings.dns_propagation_stable_seconds,
                        self.settings.dns_propagation_stable_seconds,
                    )
                if time.time() - stable_since >= self.settings.dns_propagation_stable_seconds:
                    logger.info("DNS 记录传播完成 / DNS propagation complete: %s", record_name)
                    return
            else:
                stable_since = None

            now = time.time()
            if now - last_log_time >= 30:
                pending_authoritative = [item["nameserver"] for item in authoritative_results if not item["ok"]]
                pending_recursive = [item["nameserver"] for item in recursive_results if not item["ok"]]
                logger.info(
                    "DNS 传播等待中 / Waiting for DNS propagation. authoritative pending=%s recursive pending=%s",
                    pending_authoritative or "none",
                    pending_recursive or "none",
                )
                last_log_time = now

            time.sleep(self.settings.dns_propagation_interval)

        raise TimeoutError(f"DNS propagation timed out for {record_name}")

    def setup_dns_challenge(self, record_name: str, validations: list[str]) -> None:
        resource_group_name, zone_name, relative_name = self._get_managed_record_location(record_name)
        desired_values = self._get_existing_txt_values(resource_group_name, zone_name, relative_name)
        desired_values.add(self.CHALLENGE_PLACEHOLDER_VALUE)
        desired_values.update(validations)
        record_set = {
            "ttl": 30,
            "txt_records": [{"value": [value]} for value in sorted(desired_values)],
        }
        self.dns_client.record_sets.create_or_update(
            resource_group_name=resource_group_name,
            zone_name=zone_name,
            relative_record_set_name=relative_name,
            record_type="TXT",
            parameters=record_set,
        )
        logger.info("DNS TXT 记录已更新 / DNS TXT record updated: %s", record_name)
        self._wait_for_dns_propagation(record_name, validations)

    def cleanup_dns_challenge(self, record_name: str, validations: list[str]) -> None:
        resource_group_name, zone_name, relative_name = self._get_managed_record_location(record_name)
        remaining_values = self._get_existing_txt_values(resource_group_name, zone_name, relative_name)
        remaining_values.difference_update(validations)
        remaining_values.add(self.CHALLENGE_PLACEHOLDER_VALUE)
        record_set = {
            "ttl": 30,
            "txt_records": [{"value": [value]} for value in sorted(remaining_values)],
        }
        self.dns_client.record_sets.create_or_update(
            resource_group_name=resource_group_name,
            zone_name=zone_name,
            relative_record_set_name=relative_name,
            record_type="TXT",
            parameters=record_set,
        )

    def get_certificate(self) -> tuple[str, str]:
        account_key = self.generate_account_key()
        net = client.ClientNetwork(account_key)
        directory = client.ClientV2.get_directory(self.settings.acme_directory_url, net)
        acme_client = client.ClientV2(directory, net=net)
        acme_client.new_account(
            messages.NewRegistration.from_data(email=self.settings.acme_email, terms_of_service_agreed=True)
        )

        cert_private_key = self.generate_private_key()
        csr = self.create_csr(cert_private_key, self.settings.acme_domains)
        order = acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))

        challenge_entries: list[tuple[str, object, str]] = []
        record_validations: dict[str, list[str]] = {}

        for authorization in order.authorizations:
            domain = authorization.body.identifier.value
            dns_challenge = None
            for challenge in authorization.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    dns_challenge = challenge
                    break
            if not dns_challenge:
                raise ValueError(f"DNS challenge not found for {domain}")

            validation = dns_challenge.validation(account_key)
            display_name = f"*.{domain}" if getattr(authorization.body, "wildcard", False) else domain
            challenge_entries.append((display_name, dns_challenge, validation))
            record_name = f"_acme-challenge.{domain}"
            record_validations.setdefault(record_name, []).append(validation)

        try:
            for record_name, validations in record_validations.items():
                self.setup_dns_challenge(record_name, validations)

            for display_name, dns_challenge, _validation in challenge_entries:
                logger.info("提交 ACME challenge / Submitting ACME challenge: %s", display_name)
                acme_client.answer_challenge(dns_challenge, dns_challenge.response(account_key))

            finalize_deadline = datetime.now() + timedelta(seconds=self.settings.acme_validation_timeout)
            order = acme_client.poll_and_finalize(order, deadline=finalize_deadline)
        except errors.TimeoutError:
            logger.exception("Let's Encrypt authorization timed out")
            raise
        finally:
            for record_name, validations in record_validations.items():
                self.cleanup_dns_challenge(record_name, validations)

        certificate = order.fullchain_pem
        if "ISRG Root X1" not in certificate:
            certificate = certificate.rstrip() + "\n\n" + ISRG_ROOT_X1 + "\n"

        private_key_pem = cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return certificate, private_key_pem

    def upload_to_keyvault(self, certificate_pem: str, private_key_pem: str) -> None:
        cert_objects = _parse_cert_chain(certificate_pem)
        main_cert = cert_objects[0]
        ca_certs = cert_objects[1:] if len(cert_objects) > 1 else None
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=main_cert,
            cas=ca_certs,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.cert_client.import_certificate(
            certificate_name=self.settings.certificate_name,
            certificate_bytes=pkcs12_data,
        )
        logger.info("证书已上传到 Key Vault / Certificate uploaded to Key Vault: %s", self.settings.certificate_name)

    def create_pfx(self, certificate_pem: str, private_key_pem: str, cert_dir: str) -> str:
        if not self.settings.pfx_password:
            raise ValueError("PFX_PASSWORD is required when SAVE_LOCAL_CERTS=true")
        cert_objects = _parse_cert_chain(certificate_pem)
        main_cert = cert_objects[0]
        ca_certs = cert_objects[1:] if len(cert_objects) > 1 else None
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=main_cert,
            cas=ca_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(self.settings.pfx_password.encode()),
        )
        pfx_file = os.path.join(cert_dir, "certificate.pfx")
        with open(pfx_file, "wb") as file_handle:
            file_handle.write(pfx_data)
        return pfx_file

    def save_certificates_locally(self, certificate_pem: str, private_key_pem: str) -> None:
        current_date = datetime.now().strftime("%Y-%m")
        cert_dir = os.path.join(self.settings.cert_output_dir, current_date)
        os.makedirs(cert_dir, exist_ok=True)
        with open(os.path.join(cert_dir, "certificate.pem"), "w", encoding="utf-8") as file_handle:
            file_handle.write(certificate_pem)
        with open(os.path.join(cert_dir, "private_key.pem"), "w", encoding="utf-8") as file_handle:
            file_handle.write(private_key_pem)
        self.create_pfx(certificate_pem, private_key_pem, cert_dir)

    def run(self) -> None:
        logger.info("检查证书状态... / Checking certificate status...")
        if not self.check_certificate_expiry(self.settings.renewal_days_before_expiry):
            logger.info("证书仍然有效，无需更新 / Certificate is still valid, no renewal needed")
            return

        logger.info("开始获取 Let's Encrypt 证书... / Starting to obtain Let's Encrypt certificate...")
        certificate_pem, private_key_pem = self.get_certificate()

        if self.settings.save_local_certs:
            logger.info("保存证书到本地 / Saving certificates locally")
            self.save_certificates_locally(certificate_pem, private_key_pem)

        logger.info("上传证书到 Azure Key Vault / Uploading certificate to Azure Key Vault")
        self.upload_to_keyvault(certificate_pem, private_key_pem)
        logger.info("证书更新完成 / Certificate renewal completed")
