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
        """生成RSA私钥"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def generate_account_key(self):
        """生成ACME账户密钥"""
        private_key = self.generate_private_key()
        return jose.JWKRSA(key=private_key)
    
    def check_certificate_expiry(self, days_before_expiry=30):
        """检查证书是否即将过期"""
        try:
            # 获取Key Vault中的证书
            certificate = self.cert_client.get_certificate(
                certificate_name=self.config['azure']['certificate_name']
            )
            
            # 检查过期时间
            expiry_date = certificate.properties.expires_on
            current_date = datetime.now(expiry_date.tzinfo)
            days_until_expiry = (expiry_date - current_date).days
            
            print(f"证书过期时间: {expiry_date}")
            print(f"距离过期还有: {days_until_expiry} 天")
            
            if days_until_expiry <= days_before_expiry:
                print(f"证书将在 {days_until_expiry} 天内过期，需要更新")
                return True
            else:
                print(f"证书还有 {days_until_expiry} 天过期，无需更新")
                return False
                
        except ResourceNotFoundError:
            print("未找到证书，需要创建新证书")
            return True
        except Exception as e:
            print(f"检查证书时出错: {e}")
            print("无法检查证书状态，将继续更新")
            return True

    def create_csr(self, private_key, domains):
        """创建证书签名请求"""
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
        """设置DNS TXT记录用于验证"""
        # 处理通配符域名，将 *.domain.com 转换为 domain.com
        if domain.startswith('*.'):
            domain = domain[2:]  # 移除 '*.' 前缀
        
        record_name = f"_acme-challenge.{domain}"
        
        # 创建TXT记录
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
        
        print(f"DNS TXT记录已创建: {record_name} = {validation}")
        time.sleep(60)  # 等待DNS传播

    def cleanup_dns_challenge(self, domain):
        """清理DNS TXT记录"""
        # 处理通配符域名，将 *.domain.com 转换为 domain.com
        if domain.startswith('*.'):
            domain = domain[2:]  # 移除 '*.' 前缀
        
        record_name = f"_acme-challenge.{domain}"
        
        try:
            self.dns_client.record_sets.delete(
                resource_group_name=self.config['dns']['resource_group'],
                zone_name=self.config['dns']['zone_name'],
                relative_record_set_name=record_name.replace(f".{self.config['dns']['zone_name']}", ""),
                record_type="TXT"
            )
            print(f"DNS TXT记录已删除: {record_name}")
        except Exception as e:
            print(f"删除DNS记录时出错: {e}")

    def get_certificate(self):
        """从Let's Encrypt获取证书"""
        # 生成账户密钥
        account_key = self.generate_account_key()
        
        # 创建网络客户端
        net = client.ClientNetwork(account_key)
        
        # 获取目录
        directory = client.ClientV2.get_directory(
            self.config['acme']['directory_url'], net
        )
        
        # 创建ACME客户端
        acme_client = client.ClientV2(directory, net=net)
        
        # 注册账户
        registration = acme_client.new_account(
            messages.NewRegistration.from_data(
                email=self.config['acme']['email'],
                terms_of_service_agreed=True
            )
        )
        
        # 生成证书私钥
        cert_private_key = self.generate_private_key()
        
        # 创建CSR
        csr = self.create_csr(cert_private_key, self.config['acme']['domains'])
        
        # 将CSR转换为PEM格式
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # 请求证书
        order = acme_client.new_order(csr_pem)
        
        # 处理挑战
        for authorization in order.authorizations:
            domain = authorization.body.identifier.value
            
            # 获取DNS挑战
            dns_challenge = None
            for challenge in authorization.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    dns_challenge = challenge
                    break
            
            if not dns_challenge:
                raise Exception(f"未找到DNS挑战: {domain}")
            
            # 计算验证值
            validation = dns_challenge.validation(account_key)
            
            # 设置DNS记录
            self.setup_dns_challenge(domain, validation)
            
            # 响应挑战
            acme_client.answer_challenge(dns_challenge, dns_challenge.response(account_key))
        
        # 等待验证完成
        order = acme_client.poll_and_finalize(order)
        
        # 清理DNS记录
        for domain in self.config['acme']['domains']:
            self.cleanup_dns_challenge(domain)
        
        # 获取证书
        certificate = order.fullchain_pem
        private_key_pem = cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return certificate, private_key_pem

    def upload_to_keyvault(self, certificate_pem, private_key_pem):
        """上传证书到Azure Key Vault"""
        # 合并证书和私钥为PKCS12格式
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        
        # 解析证书和私钥
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        
        # 创建PKCS12
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 上传到Key Vault
        self.cert_client.import_certificate(
            certificate_name=self.config['azure']['certificate_name'],
            certificate_bytes=pkcs12_data
        )
        
        print(f"证书已成功上传到Key Vault: {self.config['azure']['certificate_name']}")

    def save_certificates_locally(self, certificate_pem, private_key_pem):
        """保存证书到本地cert/yyyy-mm目录"""
        # 创建目录路径
        current_date = datetime.now()
        cert_dir = f"cert/{current_date.strftime('%Y-%m')}"
        os.makedirs(cert_dir, exist_ok=True)
        
        # 保存证书文件
        cert_file = os.path.join(cert_dir, "certificate.pem")
        key_file = os.path.join(cert_dir, "private_key.pem")
        
        with open(cert_file, 'w') as f:
            f.write(certificate_pem)
        
        with open(key_file, 'w') as f:
            f.write(private_key_pem)
        
        print(f"证书已保存到本地: {cert_dir}")

    def run(self, force_renewal=False):
        """执行完整的证书获取和上传流程"""
        try:
            print("检查证书状态...")
            
            # 检查证书是否需要更新
            if not force_renewal and not self.check_certificate_expiry():
                print("证书仍然有效，无需更新")
                return
            
            print("开始获取Let's Encrypt证书...")
            certificate_pem, private_key_pem = self.get_certificate()
            
            print("证书获取成功，正在保存到本地...")
            self.save_certificates_locally(certificate_pem, private_key_pem)
            
            print("证书获取成功，正在上传到Azure Key Vault...")
            self.upload_to_keyvault(certificate_pem, private_key_pem)
            
            print("证书更新完成！")
            
        except Exception as e:
            print(f"错误: {e}")
            raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Azure Let\'s Encrypt Certificate Manager')
    parser.add_argument('--force', '-f', action='store_true', 
                       help='强制更新证书，忽略过期检查')
    parser.add_argument('--days', '-d', type=int, default=30,
                       help='证书过期前多少天开始更新（默认: 30天）')
    
    args = parser.parse_args()
    
    manager = CertificateManager()
    
    # 设置过期检查天数
    if hasattr(manager, 'check_certificate_expiry'):
        original_check = manager.check_certificate_expiry
        manager.check_certificate_expiry = lambda: original_check(args.days)
    
    manager.run(force_renewal=args.force)