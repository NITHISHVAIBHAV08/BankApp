from OpenSSL import crypto, SSL

k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)
cert = crypto.X509()
cert.get_subject().C = "IN"
cert.get_subject().ST = "State"
cert.get_subject().L = "City"
cert.get_subject().O = "SecureBank"
cert.get_subject().CN = "localhost"
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(10*365*24*60*60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha256')

with open("server_cert.pem", "wt") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
with open("server_key.pem", "wt") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

print("✅ Certificate created!")
