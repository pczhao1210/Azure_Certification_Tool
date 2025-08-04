#!/usr/bin/env python3
import json
import os
from datetime import datetime, timedelta
from acme import client, messages, challenges
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import josepy as jose
from azure.keyvault.certificates import CertificateClient
from azure.identity import ClientSecretCredential
from azure.mgmt.dns import DnsManagementClient
from azure.core.exceptions import ResourceNotFoundError
import time
import base64

class CertificateManager:
    def __init__(self, config_path="config.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
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
            # 获取Key Vault中的证书 / Get certificate from Key Vault
            certificate = self.cert_client.get_certificate(
                certificate_name=self.config['azure']['certificate_name']
            )
            
            # 检查过期时间 / Check expiry time
            expiry_date = certificate.properties.expires_on
            current_date = datetime.now(expiry_date.tzinfo)
            days_until_expiry = (expiry_date - current_date).days
            
            print(f"证书过期时间 / Certificate expires on: {expiry_date}")
            print(f"距离过期还有 / Days until expiry: {days_until_expiry} 天 / days")
            
            if days_until_expiry <= days_before_expiry:
                print(f"证书将在 {days_until_expiry} 天内过期，需要更新 / Certificate will expire in {days_until_expiry} days, renewal needed")
                return True
            else:
                print(f"证书还有 {days_until_expiry} 天过期，无需更新 / Certificate expires in {days_until_expiry} days, no renewal needed")
                return False
                
        except ResourceNotFoundError:
            print("未找到证书，需要创建新证书 / Certificate not found, need to create new certificate")
            return True
        except Exception as e:
            print(f"检查证书时出错 / Error checking certificate: {e}")
            print("无法检查证书状态，将继续更新 / Cannot check certificate status, will continue with renewal")
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

    def setup_dns_challenge(self, domain, validation):
        """设置DNS TXT记录用于验证 / Set up DNS TXT record for validation"""
        # 处理通配符域名，将 *.domain.com 转换为 domain.com / Handle wildcard domain, convert *.domain.com to domain.com
        if domain.startswith('*.'):
            domain = domain[2:]  # 移除 '*.' 前缀 / Remove '*.' prefix
        
        record_name = f"_acme-challenge.{domain}"
        
        # 创建TXT记录 / Create TXT record
        record_set = {
            "ttl": 300,
            "txt_records": [{"value": [validation]}]
        }
        
        self.dns_client.record_sets.create_or_update(
            resource_group_name=self.config['dns']['resource_group'],
            zone_name=self.config['dns']['zone_name'],
            relative_record_set_name=record_name.replace(f".{self.config['dns']['zone_name']}", ""),
            record_type="TXT",
            parameters=record_set
        )
        
        print(f"DNS TXT记录已创建 / DNS TXT record created: {record_name} = {validation}")
        time.sleep(60)  # 等待DNS传播 / Wait for DNS propagation

    def cleanup_dns_challenge(self, domain):
        """清理DNS TXT记录 / Clean up DNS TXT record"""
        # 处理通配符域名，将 *.domain.com 转换为 domain.com / Handle wildcard domain, convert *.domain.com to domain.com
        if domain.startswith('*.'):
            domain = domain[2:]  # 移除 '*.' 前缀 / Remove '*.' prefix
        
        record_name = f"_acme-challenge.{domain}"
        
        try:
            self.dns_client.record_sets.delete(
                resource_group_name=self.config['dns']['resource_group'],
                zone_name=self.config['dns']['zone_name'],
                relative_record_set_name=record_name.replace(f".{self.config['dns']['zone_name']}", ""),
                record_type="TXT"
            )
            print(f"DNS TXT记录已删除 / DNS TXT record deleted: {record_name}")
        except Exception as e:
            print(f"删除DNS记录时出错 / Error deleting DNS record: {e}")

    def get_certificate(self):
        """从Let's Encrypt获取证书 / Get certificate from Let's Encrypt"""
        # 生成账户密钥 / Generate account key
        account_key = self.generate_account_key()
        
        # 创建网络客户端 / Create network client
        net = client.ClientNetwork(account_key)
        
        # 获取目录 / Get directory
        directory = client.ClientV2.get_directory(
            self.config['acme']['directory_url'], net
        )
        
        # 创建ACME客户端 / Create ACME client
        acme_client = client.ClientV2(directory, net=net)
        
        # 注册账户 / Register account
        registration = acme_client.new_account(
            messages.NewRegistration.from_data(
                email=self.config['acme']['email'],
                terms_of_service_agreed=True
            )
        )
        
        # 生成证书私钥 / Generate certificate private key
        cert_private_key = self.generate_private_key()
        
        # 创建CSR / Create CSR
        csr = self.create_csr(cert_private_key, self.config['acme']['domains'])
        
        # 将CSR转换为PEM格式 / Convert CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # 请求证书 / Request certificate
        order = acme_client.new_order(csr_pem)
        
        # 处理挑战 / Handle challenges
        for authorization in order.authorizations:
            domain = authorization.body.identifier.value
            
            # 获取DNS挑战 / Get DNS challenge
            dns_challenge = None
            for challenge in authorization.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    dns_challenge = challenge
                    break
            
            if not dns_challenge:
                raise Exception(f"未找到DNS挑战 / DNS challenge not found: {domain}")
            
            # 计算验证值 / Calculate validation value
            validation = dns_challenge.validation(account_key)
            
            # 设置DNS记录 / Set up DNS record
            self.setup_dns_challenge(domain, validation)
            
            # 响应挑战 / Respond to challenge
            acme_client.answer_challenge(dns_challenge, dns_challenge.response(account_key))
        
        # 等待验证完成 / Wait for validation completion
        order = acme_client.poll_and_finalize(order)
        
        # 清理DNS记录 / Clean up DNS records
        for domain in self.config['acme']['domains']:
            self.cleanup_dns_challenge(domain)
        
        # 获取证书链 / Get certificate chain
        certificate = order.fullchain_pem
        
        # 添加ISRG Root X1根证书以确保证书链完整 / Add ISRG Root X1 root certificate to ensure complete certificate chain
        isrg_root_x1 = """-----BEGIN CERTIFICATE-----
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
        
        # 检查是否已包含根证书 / Check if root certificate is already included
        if "ISRG Root X1" not in certificate:
            certificate = certificate.rstrip() + "\n\n" + isrg_root_x1 + "\n"
            print("已添加ISRG Root X1根证书 / Added ISRG Root X1 root certificate")
        
        print("获取到完整证书链（包含根证书） / Obtained complete certificate chain (including root certificate)")
        
        # 确保证书链完整 - 添加ISRG Root X1根证书 / Ensure certificate chain completeness - add ISRG Root X1 root certificate
        isrg_root_x1 = """-----BEGIN CERTIFICATE-----
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
        
        # 检查证书链是否已包含根证书 / Check if certificate chain already contains root certificate
        if "ISRG Root X1" not in certificate:
            certificate = certificate.rstrip() + "\n\n" + isrg_root_x1 + "\n"
        
        private_key_pem = cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return certificate, private_key_pem

    def upload_to_keyvault(self, certificate_pem, private_key_pem):
        """上传证书到Azure Key Vault / Upload certificate to Azure Key Vault"""
        # 合并证书和私钥为PKCS12格式 / Combine certificate and private key into PKCS12 format
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        
        # 解析证书链 / Parse certificate chain
        cert_objects = []
        cert_blocks = certificate_pem.split('-----END CERTIFICATE-----')
        
        for i, block in enumerate(cert_blocks):
            if '-----BEGIN CERTIFICATE-----' in block:
                cert_pem = block + '-----END CERTIFICATE-----'
                cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
                cert_objects.append(cert_obj)
        
        if not cert_objects:
            raise ValueError("未找到有效证书 / No valid certificates found")
        
        # 第一个证书是主证书，其余的是中间证书 / First certificate is main cert, others are intermediate certs
        main_cert = cert_objects[0]
        ca_certs = cert_objects[1:] if len(cert_objects) > 1 else None
        
        # 解析私钥 / Parse private key
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        
        # 创建PKCS12，包含完整证书链 / Create PKCS12 with complete certificate chain
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=main_cert,
            cas=ca_certs,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 上传到Key Vault / Upload to Key Vault
        self.cert_client.import_certificate(
            certificate_name=self.config['azure']['certificate_name'],
            certificate_bytes=pkcs12_data
        )
        
        print(f"证书已成功上传到Key Vault / Certificate successfully uploaded to Key Vault: {self.config['azure']['certificate_name']}")
        print(f"证书链包含 {len(cert_objects)} 个证书 / Certificate chain contains {len(cert_objects)} certificates")

    def save_certificates_locally(self, certificate_pem, private_key_pem):
        """保存证书到本地cert/yyyy-mm目录 / Save certificates to local cert/yyyy-mm directory"""
        # 创建目录路径 / Create directory path
        current_date = datetime.now()
        cert_dir = f"cert/{current_date.strftime('%Y-%m')}"
        os.makedirs(cert_dir, exist_ok=True)
        
        # 保存证书文件 / Save certificate files
        cert_file = os.path.join(cert_dir, "certificate.pem")
        key_file = os.path.join(cert_dir, "private_key.pem")
        
        with open(cert_file, 'w') as f:
            f.write(certificate_pem)
        
        with open(key_file, 'w') as f:
            f.write(private_key_pem)
        
        print(f"证书已保存到本地 / Certificate saved locally: {cert_dir}")
        
        # 验证证书链完整性 / Verify certificate chain integrity
        cert_count = certificate_pem.count('-----BEGIN CERTIFICATE-----')
        print(f"证书链包含 {cert_count} 个证书 / Certificate chain contains {cert_count} certificates")

    def run(self, force_renewal=False):
        """执行完整的证书获取和上传流程 / Execute complete certificate acquisition and upload process"""
        try:
            print("检查证书状态... / Checking certificate status...")
            
            # 检查证书是否需要更新 / Check if certificate needs renewal
            if not force_renewal and not self.check_certificate_expiry():
                print("证书仍然有效，无需更新 / Certificate is still valid, no renewal needed")
                return
            
            print("开始获取Let's Encrypt证书... / Starting to obtain Let's Encrypt certificate...")
            certificate_pem, private_key_pem = self.get_certificate()
            
            print("证书获取成功，正在保存到本地... / Certificate obtained successfully, saving locally...")
            self.save_certificates_locally(certificate_pem, private_key_pem)
            
            print("证书获取成功，正在上传到Azure Key Vault... / Certificate obtained successfully, uploading to Azure Key Vault...")
            self.upload_to_keyvault(certificate_pem, private_key_pem)
            
            print("证书更新完成！ / Certificate renewal completed!")
            
        except Exception as e:
            print(f"错误 / Error: {e}")
            raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Azure Let\'s Encrypt Certificate Manager')
    parser.add_argument('--force', '-f', action='store_true', 
                       help='强制更新证书，忽略过期检查 / Force certificate renewal, ignore expiry check')
    parser.add_argument('--days', '-d', type=int, default=30,
                       help='证书过期前多少天开始更新（默认: 30天） / Days before expiry to start renewal (default: 30 days)')
    
    args = parser.parse_args()
    
    manager = CertificateManager()
    
    # 设置过期检查天数 / Set expiry check days
    if hasattr(manager, 'check_certificate_expiry'):
        original_check = manager.check_certificate_expiry
        manager.check_certificate_expiry = lambda: original_check(args.days)
    
    manager.run(force_renewal=args.force)