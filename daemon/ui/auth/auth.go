package auth

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// client auth types:
// https://pkg.go.dev/crypto/tls#ClientAuthType
var (
	clientAuthType = map[string]tls.ClientAuthType{
		"no-client-cert":      tls.NoClientCert,
		"req-cert":            tls.RequestClientCert,
		"req-any-cert":        tls.RequireAnyClientCert,
		"verify-cert":         tls.VerifyClientCertIfGiven,
		"req-and-verify-cert": tls.RequireAndVerifyClientCert,
	}
)

const (
	// AuthSimple will use WithInsecure()
	AuthSimple = "simple"

	// AuthTLSSimple will use a common CA certificate, shared between the server
	// and all the clients.
	AuthTLSSimple = "tls-simple"

	// AuthTLSMutual will use a CA certificate and a client cert and key
	// to authenticate each client.
	AuthTLSMutual = "tls-mutual"
)

// New returns the configuration that the UI will use
// to connect with the server.
func New(config *config.Config) (grpc.DialOption, error) {
	config.RLock()

	credsType := config.Server.Authentication.Type
	tlsOpts := config.Server.Authentication.TLSOptions

	config.RUnlock()

	if credsType == "" || credsType == AuthSimple {
		log.Debug("UI auth: simple")
		return grpc.WithInsecure(), nil
	}
	certPool := x509.NewCertPool()

	// use CA certificate to authenticate clients if supplied
	if tlsOpts.CACert != "" {
		if caPem, err := ioutil.ReadFile(tlsOpts.CACert); err != nil {
			log.Warning("reading UI auth CA certificate (%s): %s", credsType, err)
		} else {
			if !certPool.AppendCertsFromPEM(caPem) {
				log.Warning("adding UI auth CA certificate (%s): %s", credsType, err)
			}
		}
	}

	// use server certificate to authenticate clients if supplied
	if tlsOpts.ServerCert != "" {
		if serverPem, err := ioutil.ReadFile(tlsOpts.ServerCert); err != nil {
			log.Warning("reading auth server cert: %s", err)
		} else {
			if !certPool.AppendCertsFromPEM(serverPem) {
				log.Warning("adding UI auth server cert (%s): %s", credsType, err)
			}
		}
	}

	// set config of tls credential
	// https://pkg.go.dev/crypto/tls#Config
	tlsCfg := &tls.Config{
		InsecureSkipVerify: tlsOpts.SkipVerify,
		RootCAs:            certPool,
	}

	// https://pkg.go.dev/google.golang.org/grpc/credentials#SecurityLevel
	if credsType == AuthTLSMutual {
		tlsCfg.ClientAuth = clientAuthType[tlsOpts.ClientAuthType]
		clientCert, err := tls.LoadX509KeyPair(
			tlsOpts.ClientCert,
			tlsOpts.ClientKey,
		)
		if err != nil {
			return nil, err
		}
		log.Debug("   using client cert: %s", tlsOpts.ClientCert)
		log.Debug("   using client key: %s", tlsOpts.ClientKey)
		tlsCfg.Certificates = []tls.Certificate{clientCert}
	}

	return grpc.WithTransportCredentials(
		credentials.NewTLS(tlsCfg),
	), nil
}
