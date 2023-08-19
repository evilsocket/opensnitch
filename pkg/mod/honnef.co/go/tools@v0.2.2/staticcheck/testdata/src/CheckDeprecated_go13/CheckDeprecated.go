package pkg

import (
	"crypto/x509"
	"net/http/httputil"
	"path/filepath"
)

func fn() {
	filepath.HasPrefix("", "")               // want `filepath.HasPrefix has been deprecated since Go 1.0 because it shouldn't be used:`
	_ = httputil.ErrPersistEOF               // want `httputil.ErrPersistEOF has been deprecated since Go 1.0:`
	_ = httputil.ServerConn{}                // want `httputil.ServerConn has been deprecated since Go 1.0:`
	_ = x509.CertificateRequest{}.Attributes // want `x509.CertificateRequest{}.Attributes has been deprecated since Go 1.5 and an alternative has been available since Go 1.3:`
}
