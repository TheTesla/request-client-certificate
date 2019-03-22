#!/usr/bin/env python

from OpenSSL import crypto
import requests
import requests_pkcs12

pKey = crypto.PKey()
pKey.generate_key(crypto.TYPE_RSA, 4096)


pubKey = crypto.dump_publickey(crypto.FILETYPE_PEM, pKey)
pubKeyPEM = str(pubKey.decode('utf-8'))
pubKeyFile = open("pub.pem", "w")
pubKeyFile.write(pubKeyPEM)
pubKeyFile.close()

privKey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pKey)
privKeyPEM = str(privKey.decode('utf-8'))
privKeyFile = open("priv.pem", "w")
privKeyFile.write(privKeyPEM)
privKeyFile.close()




req = crypto.X509Req()
subj = req.get_subject()

setattr(subj, "C", "DE")



extensions = [crypto.X509Extension(b"subjectAltName", False, "DNS:test.tld, DNS:tester.tld, DNS:test.srns.net".encode('ascii'))]
#extensions.append(crypto.X509Extension(b"keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment".encode('ascii')))
#extensions.append(crypto.X509Extension(b"extendedKeyUsage", False, "serverAuth, clientAuth".encode('ascii')))
#extensions.append(crypto.X509Extension(b"basicConstraints", False, "CA:FALSE".encode('ascii')))


req.add_extensions(extensions)



req.set_pubkey(pKey)
req.sign(pKey, "sha256")

csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

print(csr)

csrFile = open("test.csr", "w")
csrFile.write(str(csr.decode('utf8')))
csrFile.close()

#response = requests.post(url="https://srns.smartrns.net/genclientcert_keygen.php", data={"csr": csr, "days": 1})
#response = requests.post(url="https://gotest.smartrns.net:8443/", data={"csr": csr, "days": 360}, cert='test.p12')
response = requests_pkcs12.post(url="https://gotest.smartrns.net:8443/", data={"csr": csr, "days": 360}, pkcs12_filename='test.p12', pkcs12_password='passphrase')
print(response)
print(response.text)



cert = crypto.load_certificate(crypto.FILETYPE_PEM, response.text)
priv = crypto.load_privatekey(crypto.FILETYPE_PEM, privKeyPEM)


ext = cert.get_extension(2)
print(ext)

pfx = crypto.PKCS12()
pfx.set_privatekey(priv)
pfx.set_certificate(cert)
pfxData = pfx.export(b'passphrase')
#print(pfxData)
pfxcert = pfx.get_certificate()
print(pfxcert.get_extension(2))

with open('test.p12', 'wb') as p12File:
    p12File.write(pfxData)

