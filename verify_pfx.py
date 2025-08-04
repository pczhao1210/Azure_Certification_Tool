#!/usr/bin/env python3
"""
验证PFX文件证书链完整性 / Verify PFX file certificate chain integrity
"""
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

def verify_pfx_file(pfx_path, password="1234"):
    """
    验证PFX文件证书链 / Verify PFX file certificate chain
    """
    try:
        # 读取PFX文件 / Read PFX file
        with open(pfx_path, 'rb') as f:
            pfx_data = f.read()
        
        # 解析PFX文件 / Parse PFX file
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pfx_data, password.encode()
        )
        
        print(f"PFX文件验证 / PFX file verification: {pfx_path}")
        print(f"密码验证 / Password verification: 成功 / Success")
        
        # 显示主证书信息 / Show main certificate info
        if certificate:
            subject = certificate.subject.rfc4514_string()
            issuer = certificate.issuer.rfc4514_string()
            print(f"\n主证书 / Main certificate:")
            print(f"  主题 / Subject: {subject}")
            print(f"  颁发者 / Issuer: {issuer}")
            print(f"  有效期 / Valid from: {certificate.not_valid_before_utc} 到 / to {certificate.not_valid_after_utc}")
        
        # 显示中间证书信息 / Show intermediate certificates info
        if additional_certificates:
            print(f"\n中间证书 / Intermediate certificates ({len(additional_certificates)} 个 / certificates):")
            for i, cert in enumerate(additional_certificates, 1):
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                print(f"  证书 {i} / Certificate {i}:")
                print(f"    主题 / Subject: {subject}")
                print(f"    颁发者 / Issuer: {issuer}")
        
        # 验证证书链连续性 / Verify certificate chain continuity
        print(f"\n证书链验证 / Certificate chain verification:")
        all_certs = [certificate] + (additional_certificates or [])
        print(f"总证书数量 / Total certificates: {len(all_certs)}")
        
        # 检查证书链 / Check certificate chain
        chain_valid = True
        for i in range(len(all_certs) - 1):
            current_cert = all_certs[i]
            next_cert = all_certs[i + 1]
            
            if current_cert.issuer != next_cert.subject:
                print(f"  警告 / Warning: 证书 {i+1} 和 {i+2} 之间缺少连接 / Missing link between certificate {i+1} and {i+2}")
                chain_valid = False
        
        if chain_valid:
            print("  证书链连续性 / Chain continuity: 验证通过 / Verified")
        
        # 检查是否包含根证书 / Check if root certificate is included
        root_cert = all_certs[-1] if all_certs else None
        if root_cert and root_cert.subject == root_cert.issuer:
            print("  根证书 / Root certificate: 已包含 / Included")
        else:
            print("  根证书 / Root certificate: 未包含 / Not included")
        
        return True
        
    except Exception as e:
        print(f"验证PFX文件时出错 / Error verifying PFX file: {e}")
        return False

def main():
    """主函数 / Main function"""
    # 查找PFX文件 / Find PFX files
    import glob
    
    pfx_files = glob.glob("cert/**/certificate.pfx", recursive=True)
    
    if not pfx_files:
        print("未找到PFX文件 / No PFX files found")
        return
    
    for pfx_file in pfx_files:
        verify_pfx_file(pfx_file)
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()