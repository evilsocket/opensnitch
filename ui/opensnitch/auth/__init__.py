
import grpc

Simple = "simple"
TLSSimple = "tls-simple"
TLSMutual = "tls-mutual"


def load_file(file_path):
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except Exception as e:
        print("auth: error loading {0}: {1}".format(file_path, e))
        return None


def get_tls_credentials(server_cert, server_key):
    """return a new gRPC credentials object given a server cert and key file.
    https://grpc.io/docs/guides/auth/#python
    """
    try:
        cert = load_file(server_cert)
        cert_key = load_file(server_key)

        return grpc.ssl_server_credentials(
            (
                (
                    cert_key, cert,
                ),
            )
        )
    except Exception as e:
        print("get_tls_credentials error:", e)
        return None
