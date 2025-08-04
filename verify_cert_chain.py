#!/usr/bin/env python3
"""
验证SSL证书链完整性的工具
"""
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import sys

def verify_cert_file(cert_file_path):
    """验证本地证书文件的证书链"""
    try:
        with open(cert_file_path, 'r') as f:
            cert_data = f.read()
        
        # 统计证书数量
        cert_count = cert_data.count('-----BEGIN CERTIFICATE-----')
        print(f"证书文件包含 {cert_count} 个证书")
        
        # 解析每个证书
        cert_blocks = cert_data.split('-----END CERTIFICATE-----')
        certificates = []
        
        for i, block in enumerate(cert_blocks):
            if '-----BEGIN CERTIFICATE-----' in block:
                cert_pem = block + '-----END CERTIFICATE-----'
                try:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode())
                    certificates.append(cert)
                    
                    # 获取证书信息
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    print(f"证书 {i+1}:")
                    print(f"  主题: {subject}")
                    print(f"  颁发者: {issuer}")
                    print(f"  有效期: {cert.not_valid_before} 到 {cert.not_valid_after}")
                    print()
                except Exception as e:
                    print(f"解析证书 {i+1} 时出错: {e}")
        
        return len(certificates) >= 3  # 应该至少有3个证书：域名证书、中间证书、根证书
        
    except Exception as e:
        print(f"读取证书文件时出错: {e}")
        return False

def verify_domain_ssl(domain, port=443):
    """验证域名的SSL证书链"""
    try:
        # 创建SSL上下文
        context = ssl.create_default_context()
        
        # 连接到服务器
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # 获取证书链
                cert_der = ssock.getpeercert(binary_form=True)
                cert_chain = ssock.getpeercert_chain()
                
                print(f"域名 {domain} 的证书链:")
                print(f"证书链包含 {len(cert_chain)} 个证书")
                
                for i, cert_der in enumerate(cert_chain):
                    cert = x509.load_der_x509_certificate(cert_der)
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    print(f"证书 {i+1}:")
                    print(f"  主题: {subject}")
                    print(f"  颁发者: {issuer}")
                    print()
                
                return len(cert_chain) >= 2  # 至少应该有域名证书和中间证书
                
    except Exception as e:
        print(f"验证域名 {domain} 的SSL证书时出错: {e}")
        return False

if __name__ == "__main__":
    print("=== SSL证书链验证工具 ===\n")
    
    # 验证本地证书文件
    cert_file = "cert/2025-08/certificate.pem"
    print("1. 验证本地证书文件:")
    file_valid = verify_cert_file(cert_file)
    print(f"本地证书文件验证结果: {'通过' if file_valid else '失败'}\n")
    
    # 如果提供了域名参数，也验证在线证书
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(f"2. 验证域名 {domain} 的在线证书:")
        online_valid = verify_domain_ssl(domain)
        print(f"在线证书验证结果: {'通过' if online_valid else '失败'}")
    else:
        print("提示: 可以提供域名参数来验证在线证书，例如:")
        print("python verify_cert_chain.py thingsbud.com")