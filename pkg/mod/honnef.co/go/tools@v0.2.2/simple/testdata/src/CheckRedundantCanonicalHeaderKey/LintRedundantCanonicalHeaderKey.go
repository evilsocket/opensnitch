package pkg

import (
	"net/http"
	"strings"
)

func fn1() {
	var headers http.Header

	// Matches
	headers.Add(http.CanonicalHeaderKey("test"), "test") // want `calling net/http.CanonicalHeaderKey on the 'key' argument of`
	headers.Del(http.CanonicalHeaderKey("test"))         // want `calling net/http.CanonicalHeaderKey on the 'key' argument of`
	headers.Get(http.CanonicalHeaderKey("test"))         // want `calling net/http.CanonicalHeaderKey on the 'key' argument of`
	headers.Set(http.CanonicalHeaderKey("test"), "test") // want `calling net/http.CanonicalHeaderKey on the 'key' argument of`

	// Non-matches
	headers.Add("test", "test")
	headers.Del("test")
	headers.Get("test")
	headers.Set("test", "test")

	headers.Add("test", http.CanonicalHeaderKey("test"))
	headers.Set("test", http.CanonicalHeaderKey("test"))

	headers.Add(http.CanonicalHeaderKey("test")+"1", "test")
	headers.Del(http.CanonicalHeaderKey("test") + "1")
	headers.Get(http.CanonicalHeaderKey("test") + "1")
	headers.Set(http.CanonicalHeaderKey("test")+"1", "test")

	headers.Add(strings.ToUpper(http.CanonicalHeaderKey("test")), "test")
	headers.Del(strings.ToUpper(http.CanonicalHeaderKey("test")))
	headers.Get(strings.ToUpper(http.CanonicalHeaderKey("test")))
	headers.Set(strings.ToUpper(http.CanonicalHeaderKey("test")), "test")
}
