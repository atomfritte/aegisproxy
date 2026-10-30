package registry

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// decompress wraps the response body in a gzip reader when the server compressed it. The size limit
// is applied to the decompressed stream by the caller, so a small gzipped body cannot expand without
// bound here.
func decompress(resp *http.Response) (io.Reader, error) {
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return gzip.NewReader(resp.Body)
	}
	return resp.Body, nil
}
