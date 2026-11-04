package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// Ported from upstream's TestParseJSONOrYAML_MaxBodyBytes (CVE-2026-33374); 11.6 reads the
// body in readConvertPrometheusBody instead of parseJSONOrYAML.
func TestReadConvertPrometheusBody_MaxBodyBytes(t *testing.T) {
	newCtx := func(body string) *contextmodel.ReqContext {
		req := httptest.NewRequest("POST", "http://localhost", strings.NewReader(body))
		req.Header.Set("content-type", "application/yaml")
		return &contextmodel.ReqContext{
			Context: &web.Context{
				Req:  req,
				Resp: web.NewResponseWriter("POST", httptest.NewRecorder()),
			},
			SignedInUser: &user.SignedInUser{OrgID: 1},
		}
	}

	t.Run("should reject body exceeding max bytes limit", func(t *testing.T) {
		_, err := readConvertPrometheusBody(newCtx(strings.Repeat("a", 100)), 10)
		require.Error(t, err)
		require.Contains(t, err.Error(), "request body too large")
		require.Contains(t, err.Error(), "max size 10 bytes")
	})

	t.Run("should accept body within max bytes limit", func(t *testing.T) {
		body, err := readConvertPrometheusBody(newCtx("name: test"), 1024)
		require.NoError(t, err)
		require.Equal(t, "name: test", string(body))
	})
}
