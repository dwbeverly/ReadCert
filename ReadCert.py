import ssl
import socket
import OpenSSL
from sys import argv
from datetime import datetime

#TLS handhskae to read cert, returns it in DER formatting
def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


#take filename as interactive input
if __name__ == "__main__":
    if len(argv) > 1:
        filename = argv[1]
    else:
        print('Error: must provide filename as input')
        exit(1)

#validate filename, open new file to dump results into
newname = 'CertificateResults.txt'
try:
    infile = open(filename)
except EnvironmentError as e:
    print(e)
    sys.exit(1)
print("\nThe file ({}) is valid.".format(filename))
print("\n")
o = open(newname, 'w')

#loop through file, read remote cert, load into new text file
for line in infile:
    host = line.strip()
    try:
        certificate = get_certificate(host)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

        result = {
        'serialNumber': x509.get_serial_number(),
        'notBefore': datetime.strptime(x509.get_notBefore(), '%Y%m%d%H%M%SZ'),
        'notAfter': datetime.strptime(x509.get_notAfter(), '%Y%m%d%H%M%SZ'),
        }

        extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
        extension_data = {e.get_short_name(): str(e) for e in extensions}
        result.update(extension_data)
        o.write("{0}, {1}, \n".format(host,result))
    except EnvironmentError as e:
        o.write("{0},Unavailable,\n".format(host))
        continue
else:
    print("The script has finished running. The results have been stored in {0}\n".format(newname))
o.close()
