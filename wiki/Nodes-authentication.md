## Nodes authentication (added in v1.6.1)

Since v1.6.1 you can encrypt communications with TLS/SSL certificates.

There are 3 authentication types: simple, tls-simple and tls-mutual.

 - 'simple' wont't cypher communications.
 - 'tls-simple' uses a key and a certificate for the server, and a
   common CA certificate or the server certificate to authenticate all
   nodes.
 - 'tls-mutual' uses a server key and a certificate for the server, and a
   client key and certificate per node.

There are 2 options to verify how gRPC validates credentials:
 - SkipVerify: https://pkg.go.dev/crypto/tls#Config
 - ClientAuthType: https://pkg.go.dev/crypto/tls#ClientAuthType


## Configuration examples

'tls-simple' configuration example sharing a CA certificate with the nodes:
```json
    "Server": {
        "Address": "127.0.0.1:12345",
        "Authentication": {
            "Type": "tls-mutual",
            "TLSOptions": {
                "CACert": "/etc/opensnitchd/certs/ca-cert.pem",
                "SkipVerify": false,
                "ClientAuthType": "req-and-verify-cert"
            }
        }
    }
```

You can also use the server public certificate to authenticate all nodes, by replacing `"CACert"` with `"ServerCert"`:
    `"ServerCert": "/etc/opensnitchd/certs/server-cert.pem",`
 
'tls-mutual' configuration example:
```json
    "Server": {
        "Address": "127.0.0.1:12345",
        "Authentication": {
            "Type": "tls-mutual",
            "TLSOptions": {
                "CACert": "/etc/opensnitchd/certs/ca-cert.pem",
                "ServerCert": "/etc/opensnitchd/certs/server-cert.pem",
                "ClientCert": "/etc/opensnitchd/certs/client-cert.pem",
                "ClientKey": "/etc/opensnitchd/certs/client-key.pem",
                "SkipVerify": false,
                "ClientAuthType": "req-and-verify-cert"
            }
        }
    }
 ```

## Generating TLS certificates
(the following instructions are taken from [this great post from Tech School](https://dev.to/techschoolguru/how-to-secure-grpc-connection-with-ssl-tls-in-go-4ph), slightly modified for simplicity)

##### CA and server certs:
```bash
# 1. Generate CA's private key and self-signed certificate
~ $ openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca-key.pem -out ca-cert.pem  -subj "/CN=localhost"

# echo "CA's self-signed certificate"
# openssl x509 -in ca-cert.pem -noout -text

# 2. Generate web server's private key and certificate signing request (CSR)
~ $ openssl req -newkey rsa:4096 -nodes -keyout server-key.pem -out server-req.pem  -subj "/CN=localhost"

# 3. Add localhost and 127.0.0.1 as Subject Alternative Name
# If we don't add this, the authentication will fail with "SSLV3_ALERT_BAD_CERTIFICATE".
# The DNS entry can be ommited, but IP.1: no.
# If the GUI is listening on another IP, set IP.1: to the server IP.
~ $ echo "subjectAltName=DNS:localhost,IP.1:127.0.0.1" > server-ext.cnf

# 4. Use CA's private key to sign web server's CSR and get back the signed certificate
~ $ openssl x509 -req -in server-req.pem -days 60 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf

#echo "Server's signed certificate"
#openssl x509 -in server-cert.pem -noout -text
```

Now you can use the files `ca-cert.pem`, `server-cert.pem` and `server-key.pem` to encrypt communications using the `tls-simple` configuration.
You can distribute either the `ca-cert.pem` or `server-cert.pem` to the nodes.

#### Client keys and certificates:
```bash
# 4. Generate client's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout client-key.pem -out client-req.pem -subj "/CN=client1"

# 5. Use CA's private key to sign client's CSR and get back the signed certificate
openssl x509 -req -in client-req.pem -days 60 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem
```

You can use this key and certificate to authenticate one node.

Replicate steps 4) and 5) for adding more nodes.

#### Notes

These keys and certificates must be only readable by the user root, and your user.

You can place for example the node certs under `/etc/opensnitchd/certs/`, and reference them from the config:
  `"ServerCert": "/etc/opensnitchd/certs/server-cert.pem"`

`~ $ sudo chmod 600 /etc/opensnitchd/certs/*`
