#!/usr/bin/env python

from OpenSSL import crypto
import requests

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

response = requests.post(url="https://srns.smartrns.net/genclientcert_keygen.php", data={"pubkey": pubKeyPEM, "cn": "test2", "days": 1})
print(response)
print(response.text)



cert = crypto.load_certificate(crypto.FILETYPE_PEM, response.text)
priv = crypto.load_privatekey(crypto.FILETYPE_PEM, privKeyPEM)


pfx = crypto.PKCS12()
pfx.set_privatekey(priv)
pfx.set_certificate(cert)
pfxData = pfx.export(b'passphrase')
print(pfxData)


with open('test.p12', 'wb') as p12File:
    p12File.write(pfxData)

