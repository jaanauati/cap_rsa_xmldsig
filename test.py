#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D Yates
# andrewyates.name@gmail.com
"""Working example of xmldsig and rsa_x509_pem modules to sign XML documents.

See:
- https://github.com/andrewdyates/rsa_x509_pem
- https://github.com/andrewdyates/xmldsig
"""
import xmldsig
import rsa_x509_pem

def main():
  
  # 1. Read XML
  # ========
  xml = open("samples/second-unsigned.xml").read()

  
  # 2. Load RSA private key for signatures
  # ==================================
  data = open("samples/privkey_1_rsa_2048.pem").read()
  key_dict = rsa_x509_pem.parse(data)
  key = rsa_x509_pem.get_key(key_dict)

  
  # 3. Generate key info: choose one:
  # ==============================
  # - Style #1: embed RSA public key into signature itself
  key_info_xml1 = xmldsig.key_info_xml_rsa(key_dict['modulus'], key_dict['publicExponent'])
  
  # - Style #2: embed matching certificate from file into signature
  cert_lines = open("samples/rsa_cert_1_2048.pem").readlines()
  cert = ''.join([s.strip() for s in cert_lines[1:-1]])
  key_info_xml2 = xmldsig.key_info_xml_cert(cert, "SubjectName")
  # note: subject_name = SubjectName to match provided example "samples/second.xml"

  # - Assume Style #2...
  key_info_xml = key_info_xml2

  
  # 4. Sign XML Document
  # ==============================
  signed_xml = xmldsig.sign(xml, key.decrypt, key_info_xml, key.size(), "Name")
  print signed_xml

  # 5. Verify signature
  is_verified = xmldsig.verify(signed_xml, lambda x: key.encrypt(x, None), key.size())
  
  assert(is_verified)
  

if __name__ == '__main__':
  main()
