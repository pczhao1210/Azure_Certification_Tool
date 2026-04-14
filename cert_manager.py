#!/usr/bin/env python3
import json
import logging
import os
import glob
import time
from datetime import datetime, timedelta

from acme import client, messages, challenges, errors
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID
import josepy as jose
from azure.keyvault.certificates import CertificateClient
from azure.identity import ClientSecretCredential
from azure.mgmt.dns import DnsManagementClient
from azure.core.exceptions import ResourceNotFoundError

logger = logging.getLogger(__name__)

REQUIRED_CONFIG_KEYS = {
    'azure': ['tenant_id', 'client_id', 'client_secret', 'key_vault_url', 'certificate_name'],
    'dns': ['subscription_id', 'resource_group', 'zone_name'],
    'acme': ['email', 'domains', 'directory_url'],
}

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


def _parse_cert_chain(certificate_pem):
    """解析PEM证书链，返回证书对象列表 / Parse PEM certificate chain, return list of certificate objects"""
    cert_objects = []
    cert_blocks = certificate_pem.split('-----END CERTIFICATE-----')

    for block in cert_blocks:
        if '-----BEGIN CERTIFICATE-----' in block:
            cert_pem = block + '-----END CERTIFICATE-----'
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
            cert_objects.append(cert_obj)

    if not cert_objects:
        raise ValueError("未找到有效证书 / No valid certificates found")

    return cert_objects


def _validate_config(config):
    """校验配置文件必需字段 / Validate required config fields"""
    missing = []
    for section, keys in REQUIRED_CONFIG_KEYS.items():
        if section not in config:
            missing.append(section)
            continue
        for key in keys:
            if key not in config[section]:
                missing.append(f"{section}.{key}")
    if missing:
        raise ValueError(
            f"配置文件缺少必需字段 / Missing required config fields: {', '.join(missing)}"
        )


class CertificateManager:
    ACME_VALIDATION_TIMEOUT = 900
    CHALLENGE_TTL_SECONDS = 30
    CHALLENGE_PLACEHOLDER_VALUE = "acme-challenge-placeholder"
    DNS_PROPAGATION_TIMEOUT = 900
    DNS_PROPAGATION_INTERVAL = 15
    DNS_PROPAGATION_STABLE_SECONDS = 90

    def __init__(self, config_path="config.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)

        _validate_config(self.config)

        # 以脚本所在目录为基准路径 / Use script directory as base path
        self.base_dir = os.path.dirname(os.path.abspath(config_path))

        # PFX 密码从配置读取，无配置时要求用户传入 / PFX password from config, required if not set
        self.pfx_password = self.config.get('pfx_password')

        # Azure credentials
        self.credential = ClientSecretCredential(
            tenant_id=self.config['azure']['tenant_id'],
            client_id=self.config['azure']['client_id'],
            client_secret=self.config['azure']['client_secret']
        )

        # Key Vault client
        self.cert_client = CertificateClient(
            vault_url=self.config['azure']['key_vault_url'],
            credential=self.credential
        )

        # DNS client for challenge
        self.dns_client = DnsManagementClient(
            credential=self.credential,
            subscription_id=self.config['dns']['subscription_id']
        )

    def generate_private_key(self):
        """生成RSA私钥 / Generate RSA private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def generate_account_key(self):
        """生成ACME账户密钥 / Generate ACME account key"""
        private_key = self.generate_private_key()
        return jose.JWKRSA(key=private_key)

    def check_certificate_expiry(self, days_before_expiry=30):
        """检查证书是否即将过期 / Check if certificate is about to expire"""
        try:
            certificate = self.cert_client.get_certificate(
                certificate_name=self.config['azure']['certificate_name']
            )

            expiry_date = certificate.properties.expires_on
            current_date = datetime.now(expiry_date.tzinfo)
            days_until_expiry = (expiry_date - current_date).days

            logger.info(f"证书过期时间 / Certificate expires on: {expiry_date}")
            logger.info(f"距离过期还有 / Days until expiry: {days_until_expiry} 天 / days")

            if days_until_expiry <= days_before_expiry:
                logger.info(f"证书将在 {days_until_expiry} 天内过期，需要更新 / Certificate will expire in {days_until_expiry} days, renewal needed")
                return True
            else:
                logger.info(f"证书还有 {days_until_expiry} 天过期，无需更新 / Certificate expires in {days_until_expiry} days, no renewal needed")
                return False

        except ResourceNotFoundError:
            logger.warning("未找到证书，需要创建新证书 / Certificate not found, need to create new certificate")
            return True
        except Exception as e:
            logger.error(f"检查证书时出错 / Error checking certificate: {e}")
            logger.warning("无法检查证书状态，将继续更新 / Cannot check certificate status, will continue with renewal")
            return True

    def create_csr(self, private_key, domains):
        """创建证书签名请求 / Create Certificate Signing Request"""
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0])
        ])

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain) for domain in domains
            ]),
            critical=False
        )

        return builder.sign(private_key, hashes.SHA256())

    # Let's Encrypt 使用公共递归 DNS 验证，传播检查应查同样的目标
    # Let's Encrypt validates via public recursive DNS; propagation check should query the same
    PUBLIC_DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']

    def _describe_acme_error(self, acme_error):
        """格式化 ACME 错误对象 / Format ACME error object"""
        if acme_error is None:
            return "none"

        error_type = getattr(acme_error, 'typ', None) or getattr(acme_error, 'code', None) or type(acme_error).__name__
        detail = getattr(acme_error, 'detail', None) or str(acme_error)
        subproblems = getattr(acme_error, 'subproblems', None)
        if subproblems:
            subproblem_details = []
            for item in subproblems:
                item_type = getattr(item, 'typ', None) or getattr(item, 'code', None) or type(item).__name__
                item_detail = getattr(item, 'detail', None) or str(item)
                subproblem_details.append(f"{item_type}: {item_detail}")
            detail = f"{detail}; subproblems=[{'; '.join(subproblem_details)}]"
        return f"{error_type}: {detail}"

    def _log_authorization_states(self, acme_client, authorizations):
        """记录 ACME 授权和 challenge 详细状态 / Log ACME authorization and challenge states"""
        logger.warning("Let's Encrypt 授权详情 / Let's Encrypt authorization details:")

        for authorization in authorizations:
            try:
                current_authorization, _ = acme_client.poll(authorization)
            except Exception as exc:
                domain = authorization.body.identifier.value
                logger.warning(
                    f"无法刷新授权状态 / Failed to refresh authorization status: {domain}: {exc}"
                )
                continue

            domain = current_authorization.body.identifier.value
            status = current_authorization.body.status
            wildcard = getattr(current_authorization.body, 'wildcard', False)
            logger.warning(
                f"  域名 / Domain: {domain}, 通配符 / Wildcard: {wildcard}, 状态 / Status: {status}"
            )

            for challenge in current_authorization.body.challenges:
                challenge_type = getattr(challenge.chall, 'typ', type(challenge.chall).__name__)
                challenge_status = getattr(challenge, 'status', 'unknown')
                challenge_error = self._describe_acme_error(getattr(challenge, 'error', None))
                logger.warning(
                    f"    Challenge: {challenge_type}, 状态 / Status: {challenge_status}, 错误 / Error: {challenge_error}"
                )

    def _get_challenge_zone_settings(self):
        """获取 challenge 记录托管区域配置 / Get managed DNS zone settings for ACME challenge"""
        dns_config = self.config['dns']
        return {
            'resource_group': dns_config.get('challenge_resource_group') or dns_config['resource_group'],
            'zone_name': dns_config.get('challenge_zone_name') or dns_config['zone_name'],
        }

    def _get_relative_record_name(self, fqdn, zone_name):
        """将完整域名转换为指定区域下的相对记录名 / Convert FQDN to relative record name within zone"""
        if fqdn == zone_name:
            return '@'

        suffix = f".{zone_name}"
        if not fqdn.endswith(suffix):
            raise ValueError(
                "challenge_zone_name 必须与 ACME 验证记录名匹配。"
                "若使用独立验证区域，推荐将 zone 配置为 '_acme-challenge.<domain>' 并在主区域做 NS 委派。 / "
                "challenge_zone_name must match the ACME validation record name. "
                "For a dedicated validation zone, use '_acme-challenge.<domain>' and delegate it from the parent zone."
            )

        return fqdn[:-len(suffix)]

    def _get_managed_record_location(self, record_name):
        """解析 challenge 记录在 Azure DNS 中的实际托管位置 / Resolve the managed Azure DNS location for the challenge record"""
        zone_settings = self._get_challenge_zone_settings()
        relative_name = self._get_relative_record_name(record_name, zone_settings['zone_name'])
        return zone_settings['resource_group'], zone_settings['zone_name'], relative_name

    def _get_existing_txt_values(self, resource_group_name, zone_name, relative_name):
        """读取已存在的 TXT 值 / Read existing TXT values from Azure DNS"""
        try:
            record_set = self.dns_client.record_sets.get(
                resource_group_name=resource_group_name,
                zone_name=zone_name,
                relative_record_set_name=relative_name,
                record_type="TXT"
            )
        except ResourceNotFoundError:
            return set()

        values = set()
        for txt_record in record_set.txt_records or []:
            for value in txt_record.value or []:
                if value:
                    values.add(value)
        return values

    def _resolve_txt_values(self, fqdn, nameserver):
        """向指定 DNS 服务器查询 TXT 值 / Query TXT values from a specific DNS server"""
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.lifetime = 5
        resolver.timeout = 5

        answers = resolver.resolve(fqdn, 'TXT')
        values = set()
        for rdata in answers:
            for txt_string in rdata.strings:
                values.add(txt_string.decode())
        return values

    def _get_authoritative_nameservers(self, zone_name):
        """获取区域的权威 NS 可用 IP 列表 / Get authoritative NS reachable IP addresses for a zone"""
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.PUBLIC_DNS_SERVERS
        resolver.lifetime = 5
        resolver.timeout = 5

        answers = resolver.resolve(zone_name, 'NS')
        nameservers = []
        for record in answers:
            nameserver = record.to_text().rstrip('.')
            try:
                ns_answers = resolver.resolve(nameserver, 'A')
                for ns_record in ns_answers:
                    ns_ip = ns_record.to_text()
                    if ns_ip not in nameservers:
                        nameservers.append(ns_ip)
            except Exception as exc:
                logger.debug(
                    f"解析权威NS地址失败 / Failed to resolve authoritative NS address: {nameserver}: {exc}"
                )
        return nameservers

    def _check_dns_visibility(self, fqdn, expected_values, nameservers):
        """检查一组 DNS 服务器是否都已返回全部期望值 / Check whether all DNS servers return all expected values"""
        results = []
        for nameserver in nameservers:
            try:
                actual_values = self._resolve_txt_values(fqdn, nameserver)
                missing_values = sorted(expected_values - actual_values)
                results.append({
                    'nameserver': nameserver,
                    'ok': not missing_values,
                    'missing': missing_values,
                    'values': sorted(actual_values),
                })
            except Exception as exc:
                results.append({
                    'nameserver': nameserver,
                    'ok': False,
                    'missing': sorted(expected_values),
                    'error': str(exc),
                    'values': [],
                })
        return results

    def _wait_for_dns_propagation(self, record_name, expected_values, timeout=None, interval=None, stable_seconds=None):
        """轮询权威和公共递归 DNS，直到全部传播且稳定 / Poll authoritative and public recursive DNS until all expected values propagate and remain stable"""
        timeout = timeout or self.DNS_PROPAGATION_TIMEOUT
        interval = interval or self.DNS_PROPAGATION_INTERVAL
        stable_seconds = stable_seconds or self.DNS_PROPAGATION_STABLE_SECONDS
        fqdn = record_name
        challenge_zone_name = self._get_challenge_zone_settings()['zone_name']
        authoritative_nameservers = self._get_authoritative_nameservers(challenge_zone_name)

        logger.info(
            f"等待DNS传播至权威NS与公共递归DNS / Waiting for DNS propagation to authoritative NS and public recursive DNS: {fqdn}"
        )

        expected_values = set(expected_values)
        start = time.time()
        deadline = start + timeout
        last_log_time = start
        stable_since = None
        attempt = 0

        while time.time() < deadline:
            attempt += 1
            authoritative_results = self._check_dns_visibility(fqdn, expected_values, authoritative_nameservers)
            recursive_results = self._check_dns_visibility(fqdn, expected_values, self.PUBLIC_DNS_SERVERS)

            authoritative_ok = all(item['ok'] for item in authoritative_results)
            recursive_ok = all(item['ok'] for item in recursive_results)
            all_ok = authoritative_ok and recursive_ok

            if all_ok:
                if stable_since is None:
                    stable_since = time.time()
                    logger.info(
                        f"DNS记录已在所有权威NS和公共递归DNS可见，开始稳定观察 {stable_seconds}s / "
                        f"DNS record visible on all authoritative NS and public recursive DNS, starting {stable_seconds}s stability window: {fqdn}"
                    )
                stable_elapsed = int(time.time() - stable_since)
                if time.time() - stable_since >= stable_seconds:
                    elapsed = int(time.time() - start)
                    logger.info(
                        f"DNS记录传播并稳定完成（耗时 {elapsed}s） / DNS propagation stable after {elapsed}s: {fqdn}"
                    )
                    return True
            else:
                stable_since = None

            now = time.time()
            if now - last_log_time >= 30:
                elapsed = int(now - start)
                if stable_since is not None:
                    logger.info(
                        f"DNS稳定观察中... 已等待 {elapsed}s，稳定 {stable_elapsed}s，第 {attempt} 次查询 / "
                        f"DNS stability check in progress... {elapsed}s elapsed, stable for {stable_elapsed}s, attempt #{attempt}"
                    )
                else:
                    missing_authoritative = [item['nameserver'] for item in authoritative_results if not item['ok']]
                    missing_recursive = [item['nameserver'] for item in recursive_results if not item['ok']]
                    logger.info(
                        f"DNS传播等待中... 已等待 {elapsed}s，第 {attempt} 次查询，未就绪权威NS / authoritative NS pending: {missing_authoritative or 'none'}，"
                        f"未就绪递归DNS / recursive DNS pending: {missing_recursive or 'none'}"
                    )
                last_log_time = now

            time.sleep(interval)

        logger.warning(
            f"DNS传播超时({timeout}s)，继续执行 / DNS propagation timeout ({timeout}s), proceeding anyway"
        )
        return False

    def setup_dns_challenge(self, record_name, validations):
        """设置DNS TXT记录（支持多值）/ Set up DNS TXT record (supports multiple values)"""
        resource_group_name, zone_name, relative_name = self._get_managed_record_location(record_name)
        desired_values = self._get_existing_txt_values(resource_group_name, zone_name, relative_name)
        desired_values.add(self.CHALLENGE_PLACEHOLDER_VALUE)
        desired_values.update(validations)

        record_set = {
            "ttl": self.CHALLENGE_TTL_SECONDS,
            "txt_records": [{"value": [v]} for v in sorted(desired_values)]
        }

        self.dns_client.record_sets.create_or_update(
            resource_group_name=resource_group_name,
            zone_name=zone_name,
            relative_record_set_name=relative_name,
            record_type="TXT",
            parameters=record_set
        )

        logger.info(
            f"DNS TXT记录已更新 / DNS TXT record updated: {record_name} -> {zone_name}/{relative_name} "
            f"({len(desired_values)} 个值 / values)"
        )
        # 验证所有值都已在权威与公共递归 DNS 中稳定可见 / Verify all values are stably visible on authoritative and public recursive DNS
        self._wait_for_dns_propagation(record_name, validations)

    def cleanup_dns_challenge(self, record_name, validations):
        """清理本次 challenge 的 TXT 值，但保留占位记录 / Remove current challenge TXT values while keeping placeholder record"""
        resource_group_name, zone_name, relative_name = self._get_managed_record_location(record_name)

        try:
            remaining_values = self._get_existing_txt_values(resource_group_name, zone_name, relative_name)
            remaining_values.difference_update(validations)
            remaining_values.add(self.CHALLENGE_PLACEHOLDER_VALUE)

            record_set = {
                "ttl": self.CHALLENGE_TTL_SECONDS,
                "txt_records": [{"value": [v]} for v in sorted(remaining_values)]
            }

            self.dns_client.record_sets.create_or_update(
                resource_group_name=resource_group_name,
                zone_name=zone_name,
                relative_record_set_name=relative_name,
                record_type="TXT",
                parameters=record_set
            )
            logger.info(
                f"DNS TXT challenge值已清理，保留占位记录 / DNS TXT challenge values removed, placeholder kept: "
                f"{record_name} -> {zone_name}/{relative_name}"
            )
        except Exception as e:
            logger.error(f"删除DNS记录时出错 / Error deleting DNS record: {e}")

    def get_certificate(self):
        """从Let's Encrypt获取证书 / Get certificate from Let's Encrypt"""
        account_key = self.generate_account_key()

        net = client.ClientNetwork(account_key)

        directory = client.ClientV2.get_directory(
            self.config['acme']['directory_url'], net
        )

        acme_client = client.ClientV2(directory, net=net)

        acme_client.new_account(
            messages.NewRegistration.from_data(
                email=self.config['acme']['email'],
                terms_of_service_agreed=True
            )
        )

        cert_private_key = self.generate_private_key()

        csr = self.create_csr(cert_private_key, self.config['acme']['domains'])
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        order = acme_client.new_order(csr_pem)

        # 收集所有 DNS challenge，按记录名分组（通配符和裸域共享同一记录）
        # Collect all DNS challenges, group by record name (wildcard and bare domain share the same record)
        from collections import defaultdict
        challenge_entries = []  # [(display_name, dns_challenge, validation)]
        record_validations = defaultdict(list)  # record_name -> [validation_values]

        for authorization in order.authorizations:
            domain = authorization.body.identifier.value

            dns_challenge = None
            for challenge in authorization.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    dns_challenge = challenge
                    break

            if not dns_challenge:
                raise Exception(f"未找到DNS挑战 / DNS challenge not found: {domain}")

            validation = dns_challenge.validation(account_key)
            display_name = f"*.{domain}" if getattr(authorization.body, 'wildcard', False) else domain
            challenge_entries.append((display_name, dns_challenge, validation))

            # 通配符和裸域都映射到相同的 _acme-challenge 记录
            # Both wildcard and bare domain map to the same _acme-challenge record
            base_domain = domain
            record_name = f"_acme-challenge.{base_domain}"
            record_validations[record_name].append(validation)

        try:
            # 批量创建 DNS 记录（同名记录合并多个 TXT 值）
            # Batch create DNS records (merge multiple TXT values for same record name)
            for record_name, validations in record_validations.items():
                self.setup_dns_challenge(record_name, validations)

            # DNS 传播确认后，统一应答所有 challenge
            # After DNS propagation confirmed, answer all challenges
            for display_name, dns_challenge, validation in challenge_entries:
                logger.info(f"提交ACME challenge应答 / Submitting ACME challenge response: {display_name}")
                acme_client.answer_challenge(dns_challenge, dns_challenge.response(account_key))

            # Azure DNS SOA 最小 TTL 当前为 300s，LE 若命中负缓存，5 分钟窗口会过紧
            # Azure DNS SOA minimum TTL is currently 300s; a 5-minute window is too tight if LE hits negative cache
            finalize_deadline = datetime.now() + timedelta(seconds=self.ACME_VALIDATION_TIMEOUT)
            logger.info(
                f"等待Let's Encrypt完成授权，最长 {self.ACME_VALIDATION_TIMEOUT}s / "
                f"Waiting up to {self.ACME_VALIDATION_TIMEOUT}s for Let's Encrypt authorization"
            )
            order = acme_client.poll_and_finalize(order, deadline=finalize_deadline)
        except errors.TimeoutError:
            logger.error(
                "Let's Encrypt 在超时时间内未完成授权。"
                "这通常表示 CA 侧递归 DNS 仍未看到最新 TXT，或仍命中了 300s 的负缓存。 / "
                "Let's Encrypt did not finish authorization before the deadline. "
                "This usually means the CA-side recursive DNS still could not see the latest TXT records, "
                "or was still serving a 300s negative cache entry."
            )
            self._log_authorization_states(acme_client, order.authorizations)
            raise
        except errors.ValidationError:
            self._log_authorization_states(acme_client, order.authorizations)
            raise
        finally:
            # 按记录名去重清理 DNS / Deduplicate cleanup by record name
            for record_name, validations in record_validations.items():
                self.cleanup_dns_challenge(record_name, validations)

        certificate = order.fullchain_pem

        # 添加ISRG Root X1根证书以确保证书链完整 / Add ISRG Root X1 root certificate to ensure complete certificate chain
        if "ISRG Root X1" not in certificate:
            certificate = certificate.rstrip() + "\n\n" + ISRG_ROOT_X1 + "\n"
            logger.info("已添加ISRG Root X1根证书 / Added ISRG Root X1 root certificate")

        logger.info("获取到完整证书链（包含根证书） / Obtained complete certificate chain (including root certificate)")

        private_key_pem = cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        return certificate, private_key_pem

    def upload_to_keyvault(self, certificate_pem, private_key_pem):
        """上传证书到Azure Key Vault / Upload certificate to Azure Key Vault"""
        cert_objects = _parse_cert_chain(certificate_pem)
        main_cert = cert_objects[0]
        ca_certs = cert_objects[1:] if len(cert_objects) > 1 else None

        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=main_cert,
            cas=ca_certs,
            encryption_algorithm=serialization.NoEncryption()
        )

        self.cert_client.import_certificate(
            certificate_name=self.config['azure']['certificate_name'],
            certificate_bytes=pkcs12_data
        )

        logger.info(f"证书已成功上传到Key Vault / Certificate successfully uploaded to Key Vault: {self.config['azure']['certificate_name']}")
        logger.info(f"证书链包含 {len(cert_objects)} 个证书 / Certificate chain contains {len(cert_objects)} certificates")

    def create_pfx(self, certificate_pem, private_key_pem, cert_dir, password=None):
        """生成PFX文件 / Generate PFX file"""
        password = password or self.pfx_password
        if not password:
            raise ValueError(
                "未设置PFX密码，请在config.json中设置pfx_password字段或通过--pfx-password参数指定 / "
                "PFX password not set. Set 'pfx_password' in config.json or use --pfx-password argument"
            )

        cert_objects = _parse_cert_chain(certificate_pem)
        main_cert = cert_objects[0]
        ca_certs = cert_objects[1:] if len(cert_objects) > 1 else None

        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=main_cert,
            cas=ca_certs,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        pfx_file = os.path.join(cert_dir, "certificate.pfx")
        with open(pfx_file, 'wb') as f:
            f.write(pfx_data)

        logger.info(f"PFX文件已生成 / PFX file generated: {pfx_file}")
        return pfx_file

    def save_certificates_locally(self, certificate_pem, private_key_pem):
        """保存证书到本地cert/yyyy-mm目录 / Save certificates to local cert/yyyy-mm directory"""
        current_date = datetime.now()
        cert_dir = os.path.join(self.base_dir, "cert", current_date.strftime('%Y-%m'))
        os.makedirs(cert_dir, exist_ok=True)

        cert_file = os.path.join(cert_dir, "certificate.pem")
        key_file = os.path.join(cert_dir, "private_key.pem")

        with open(cert_file, 'w') as f:
            f.write(certificate_pem)

        with open(key_file, 'w') as f:
            f.write(private_key_pem)

        logger.info(f"证书已保存到本地 / Certificate saved locally: {cert_dir}")

        cert_count = certificate_pem.count('-----BEGIN CERTIFICATE-----')
        logger.info(f"证书链包含 {cert_count} 个证书 / Certificate chain contains {cert_count} certificates")

        self.create_pfx(certificate_pem, private_key_pem, cert_dir)

        return cert_dir

    def verify_cert_chain(self, cert_file_path):
        """验证证书链完整性 / Verify certificate chain integrity"""
        try:
            with open(cert_file_path, 'r') as f:
                cert_data = f.read()

            certificates = _parse_cert_chain(cert_data)
            logger.info(f"证书文件包含 {len(certificates)} 个证书 / Certificate file contains {len(certificates)} certificates")

            for i, cert in enumerate(certificates):
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                logger.info(f"证书 {i+1} / Certificate {i+1}:")
                logger.info(f"  主题 / Subject: {subject}")
                logger.info(f"  颁发者 / Issuer: {issuer}")
                logger.info(f"  有效期 / Valid: {cert.not_valid_before_utc} 到 / to {cert.not_valid_after_utc}")

            # 验证签名链：每个证书的颁发者应与下一个证书的主题匹配
            # Verify signature chain: each cert's issuer should match the next cert's subject
            valid = True
            for i in range(len(certificates) - 1):
                if certificates[i].issuer != certificates[i + 1].subject:
                    logger.warning(
                        f"证书链断裂 / Chain broken: 证书 {i+1} 的颁发者与证书 {i+2} 的主题不匹配 / "
                        f"Certificate {i+1}'s issuer does not match certificate {i+2}'s subject"
                    )
                    valid = False

            if valid:
                logger.info("证书链验证通过 / Certificate chain validation passed")
            return valid

        except Exception as e:
            logger.error(f"验证证书链时出错 / Error verifying certificate chain: {e}")
            return False

    def verify_pfx(self, pfx_path, password=None):
        """验证PFX文件 / Verify PFX file"""
        try:
            password = password or self.pfx_password
            if not password:
                raise ValueError(
                    "未设置PFX密码 / PFX password not set. "
                    "Set 'pfx_password' in config.json or use --pfx-password argument"
                )

            with open(pfx_path, 'rb') as f:
                pfx_data = f.read()

            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                pfx_data, password.encode()
            )

            logger.info(f"PFX文件验证 / PFX file verification: {pfx_path}")
            logger.info(f"密码验证 / Password verification: 成功 / Success")

            if certificate:
                subject = certificate.subject.rfc4514_string()
                issuer = certificate.issuer.rfc4514_string()
                logger.info(f"主证书 / Main certificate:")
                logger.info(f"  主题 / Subject: {subject}")
                logger.info(f"  颁发者 / Issuer: {issuer}")
                logger.info(f"  有效期 / Valid: {certificate.not_valid_before_utc} 到 / to {certificate.not_valid_after_utc}")

            if additional_certificates:
                logger.info(f"中间证书 / Intermediate certificates ({len(additional_certificates)} 个 / certificates):")
                for i, cert in enumerate(additional_certificates, 1):
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    logger.info(f"  证书 {i} / Certificate {i}:")
                    logger.info(f"    主题 / Subject: {subject}")
                    logger.info(f"    颁发者 / Issuer: {issuer}")

            all_certs = [certificate] + (additional_certificates or [])
            logger.info(f"总证书数量 / Total certificates: {len(all_certs)}")

            return True
        except Exception as e:
            logger.error(f"验证PFX文件时出错 / Error verifying PFX file: {e}")
            return False

    def run(self, force_renewal=False, verify_chain=False, verify_pfx_files=False, days_before_expiry=30):
        """执行完整的证书获取和上传流程 / Execute complete certificate acquisition and upload process"""
        try:
            if verify_chain:
                logger.info("=== 验证证书链 / Verifying Certificate Chain ===")
                cert_files = glob.glob(os.path.join(self.base_dir, "cert/**/certificate.pem"), recursive=True)
                if cert_files:
                    for cert_file in cert_files:
                        logger.info(f"验证文件 / Verifying file: {cert_file}")
                        self.verify_cert_chain(cert_file)
                        logger.info("-" * 50)
                else:
                    logger.warning("未找到证书文件 / No certificate files found")
                return

            if verify_pfx_files:
                logger.info("=== 验证PFX文件 / Verifying PFX Files ===")
                pfx_files = glob.glob(os.path.join(self.base_dir, "cert/**/certificate.pfx"), recursive=True)
                if pfx_files:
                    for pfx_file in pfx_files:
                        logger.info(f"验证文件 / Verifying file: {pfx_file}")
                        self.verify_pfx(pfx_file)
                        logger.info("-" * 50)
                else:
                    logger.warning("未找到PFX文件 / No PFX files found")
                return

            logger.info("检查证书状态... / Checking certificate status...")

            if not force_renewal and not self.check_certificate_expiry(days_before_expiry):
                logger.info("证书仍然有效，无需更新 / Certificate is still valid, no renewal needed")
                return

            logger.info("开始获取Let's Encrypt证书... / Starting to obtain Let's Encrypt certificate...")
            certificate_pem, private_key_pem = self.get_certificate()

            logger.info("证书获取成功，正在保存到本地... / Certificate obtained successfully, saving locally...")
            cert_dir = self.save_certificates_locally(certificate_pem, private_key_pem)

            logger.info("证书获取成功，正在上传到Azure Key Vault... / Certificate obtained successfully, uploading to Azure Key Vault...")
            self.upload_to_keyvault(certificate_pem, private_key_pem)

            logger.info("证书更新完成！ / Certificate renewal completed!")

        except Exception as e:
            logger.error(f"错误 / Error: {e}")
            raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Azure Let\'s Encrypt Certificate Manager')
    parser.add_argument('--force', '-f', action='store_true',
                        help='强制更新证书，忽略过期检查 / Force certificate renewal, ignore expiry check')
    parser.add_argument('--days', '-d', type=int, default=30,
                        help='证书过期前多少天开始更新（默认: 30天） / Days before expiry to start renewal (default: 30 days)')
    parser.add_argument('--verify-chain', action='store_true',
                        help='验证证书链完整性 / Verify certificate chain integrity')
    parser.add_argument('--verify-pfx', action='store_true',
                        help='验证PFX文件 / Verify PFX files')
    parser.add_argument('--pfx-password', type=str, default=None,
                        help='PFX文件密码 / PFX file password')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='输出详细日志（含Azure SDK调试信息） / Verbose output with Azure SDK debug logs')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        # 默认抑制第三方库的冗长日志 / Suppress verbose third-party logs by default
        logging.getLogger('azure').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)

    manager = CertificateManager()
    if args.pfx_password:
        manager.pfx_password = args.pfx_password

    manager.run(
        force_renewal=args.force,
        verify_chain=args.verify_chain,
        verify_pfx_files=args.verify_pfx,
        days_before_expiry=args.days,
    )
