package tempo

import (
	"context"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTempo(t *testing.T) {
	t.Run("createRequest v1 without time range - success", func(t *testing.T) {
		service := &Service{logger: backend.NewLoggerWith("logger", "tempo-test")}
		req, err := service.createRequest(context.Background(), &Datasource{}, TraceRequestApiVersionV1, "abc123", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 1, len(req.Header))
		assert.Equal(t, "/api/traces/abc123", req.URL.String())
	})

	t.Run("createRequest v1 with time range - success", func(t *testing.T) {
		service := &Service{logger: backend.NewLoggerWith("logger", "tempo-test")}
		req, err := service.createRequest(context.Background(), &Datasource{}, TraceRequestApiVersionV1, "abc123", 1, 2)
		require.NoError(t, err)
		assert.Equal(t, 1, len(req.Header))
		assert.Equal(t, "/api/traces/abc123?start=1&end=2", req.URL.String())
	})

	t.Run("createRequest v2 without time range - success", func(t *testing.T) {
		service := &Service{logger: backend.NewLoggerWith("logger", "tempo-test")}
		req, err := service.createRequest(context.Background(), &Datasource{}, TraceRequestApiVersionV2, "abc123", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 1, len(req.Header))
		assert.Equal(t, "/api/v2/traces/abc123", req.URL.String())
	})

	t.Run("createRequest rejects non-hex trace id", func(t *testing.T) {
		service := &Service{logger: backend.NewLoggerWith("logger", "tempo-test")}
		for _, id := range []string{"../../flush", "..%2f..%2fshutdown", "abc/../def", ""} {
			_, err := service.createRequest(context.Background(), &Datasource{}, TraceRequestApiVersionV2, id, 0, 0)
			require.Error(t, err, id)
		}
	})

	t.Run("createRequest v2 with time range - success", func(t *testing.T) {
		service := &Service{logger: backend.NewLoggerWith("logger", "tempo-test")}
		req, err := service.createRequest(context.Background(), &Datasource{}, TraceRequestApiVersionV2, "abc123", 1, 2)
		require.NoError(t, err)
		assert.Equal(t, 1, len(req.Header))
		assert.Equal(t, "/api/v2/traces/abc123?start=1&end=2", req.URL.String())
	})
}
