#!/usr/bin/env python3
"""
将证书和私钥合并为PFX文件 / Combine certificate and private key into PFX file
"""
import os
import glob
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

def create_pfx_from_cert_folder(cert_folder, password="1234"):
    """
    从证书文件夹创建PFX文件 / Create PFX file from certificate folder
    """
    cert_file = os.path.join(cert_folder, "certificate.pem")
    key_file = os.path.join(cert_folder, "private_key.pem")
    pfx_file = os.path.join(cert_folder, "certificate.pfx")
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"证书文件不存在 / Certificate files not found in: {cert_folder}")
        return False
    
    try:
        # 读取证书文件 / Read certificate file
        with open(cert_file, 'r') as f:
            cert_data = f.read()
        
        # 读取私钥文件 / Read private key file
        with open(key_file, 'r') as f:
            key_data = f.read()
        
        # 解析证书链 / Parse certificate chain
        cert_blocks = []
        current_cert = ""
        in_cert = False
        
        for line in cert_data.split('\n'):
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                current_cert = line + '\n'
            elif '-----END CERTIFICATE-----' in line:
                current_cert += line + '\n'
                cert_blocks.append(current_cert)
                current_cert = ""
                in_cert = False
            elif in_cert:
                current_cert += line + '\n'
        
        # 加载主证书 / Load main certificate
        main_cert = x509.load_pem_x509_certificate(cert_blocks[0].encode())
        
        # 加载中间证书 / Load intermediate certificates
        ca_certs = []
        if len(cert_blocks) > 1:
            for cert_pem in cert_blocks[1:]:
                ca_cert = x509.load_pem_x509_certificate(cert_pem.encode())
                ca_certs.append(ca_cert)
        
        # 加载私钥 / Load private key
        private_key = serialization.load_pem_private_key(key_data.encode(), password=None)
        
        # 创建PFX / Create PFX
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=main_cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        # 保存PFX文件 / Save PFX file
        with open(pfx_file, 'wb') as f:
            f.write(pfx_data)
        
        print(f"PFX文件已创建 / PFX file created: {pfx_file}")
        print(f"密码 / Password: {password}")
        print(f"证书链包含 {len(cert_blocks)} 个证书 / Certificate chain contains {len(cert_blocks)} certificates")
        
        return True
        
    except Exception as e:
        print(f"创建PFX文件时出错 / Error creating PFX file: {e}")
        return False

def main():
    """主函数 / Main function"""
    # 查找所有证书文件夹 / Find all certificate folders
    cert_base_dir = "cert"
    
    if not os.path.exists(cert_base_dir):
        print(f"证书目录不存在 / Certificate directory not found: {cert_base_dir}")
        return
    
    # 查找所有年月文件夹 / Find all year-month folders
    cert_folders = glob.glob(os.path.join(cert_base_dir, "*"))
    cert_folders = [f for f in cert_folders if os.path.isdir(f)]
    
    if not cert_folders:
        print("未找到证书文件夹 / No certificate folders found")
        return
    
    # 处理每个证书文件夹 / Process each certificate folder
    success_count = 0
    for folder in cert_folders:
        print(f"\n处理文件夹 / Processing folder: {folder}")
        if create_pfx_from_cert_folder(folder):
            success_count += 1
    
    print(f"\n完成 / Completed: {success_count}/{len(cert_folders)} 个PFX文件已创建 / PFX files created")

if __name__ == "__main__":
    main()