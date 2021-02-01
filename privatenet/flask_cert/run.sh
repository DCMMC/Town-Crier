openssl genrsa -out  rootCA.key 2048
openssl req -new -x509 -days 365 -key rootCA.key -out rootCA.pem   -subj '/C=UK/ST=cubic/L=London/CN=rootCA'
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out cert.csr -subj '/C=UK/ST=cubic/L=London/CN=localhost'
openssl x509 -req -days 365 -in cert.csr -CA rootCA.pem -CAkey rootCA.key -set_serial 01 -out cert.pem
rm -v *.csr
# ref: https://tls.mbed.org/discussions/bug-report-issues/issue-with-verifying-server-certificate
# rootCA.key should put into ca_bundle.h
