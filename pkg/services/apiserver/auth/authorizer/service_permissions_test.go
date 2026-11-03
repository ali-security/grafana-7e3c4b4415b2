package authorizer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHasPermissionInToken is ported from authlib authz/client_test.go (same name and cases).
// Upstream: https://github.com/grafana/authlib/blob/main/authz/client_test.go
// Inlined into service_permissions.go for v11.6.0 — keep in sync when updating that file.
func TestHasPermissionInToken(t *testing.T) {
	tests := []struct {
		name             string
		tokenPermissions []string
		group            string
		resource         string
		verb             string
		want             bool
	}{
		{
			name:             "Permission matches group/resource",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             true,
		},
		{
			name:             "Permission does not match verb",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards:list"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "update",
			want:             false,
		},
		{
			name:             "Permission matches wildcard verb",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards:*"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             true,
		},
		{
			name:             "Invalid permission missing verb",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             false,
		},
		{
			name:             "Permission on the wrong group",
			tokenPermissions: []string{"other-group.grafana.app/dashboards:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Permission on the wrong resource",
			tokenPermissions: []string{"dashboard.grafana.app/other-resource:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             false,
		},
		{
			name:             "Permission without group are skipped",
			tokenPermissions: []string{":get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Group level permission",
			tokenPermissions: []string{"dashboard.grafana.app:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "list",
			want:             true,
		},
		{
			name:             "Permission with extra parts does not match group/resource",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards/extra:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Parts need an exact match",
			tokenPermissions: []string{"dashboard.grafana.app/dash:*"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Resource specific permission should not allow access to all resources",
			tokenPermissions: []string{"dashboard.grafana.app/dashboards/dashUID:get"},
			group:            "dashboard.grafana.app",
			resource:         "dashboards",
			verb:             "get",
			want:             false,
		},
		// Wildcard group matching: *.datasource.grafana.app matches any group that has that suffix and is longer
		{
			name:             "Wildcard group allows prometheus.datasource.grafana.app for datasources:get",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:*"},
			group:            "prometheus.datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             true,
		},
		{
			name:             "Wildcard group with explicit resource and verb matches",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:get"},
			group:            "tempo.datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             true,
		},
		{
			name:             "Wildcard group with explicit resource and verb does not match wrong verb",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:get"},
			group:            "tempo.datasource.grafana.app",
			resource:         "datasources",
			verb:             "update",
			want:             false,
		},
		{
			name:             "Wildcard group allows loki.datasource.grafana.app for datasources:list",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:*"},
			group:            "loki.datasource.grafana.app",
			resource:         "datasources",
			verb:             "list",
			want:             true,
		},
		{
			name:             "Wildcard group does not allow nested prefix (foo.loki.datasource.grafana.app)",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:*"},
			group:            "foo.loki.datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Wildcard group does not allow wrong suffix (dashboard.grafana.app)",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:*"},
			group:            "dashboard.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Wildcard group does not allow request group equal to suffix (datasource.grafana.app)",
			tokenPermissions: []string{"*.datasource.grafana.app/datasources:*"},
			group:            "datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Non-allowlisted wildcard does not match (group/resource:verb)",
			tokenPermissions: []string{"*.grafana.app/datasources:get"},
			group:            "prometheus.datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Non-allowlisted wildcard does not match (group:verb)",
			tokenPermissions: []string{"*.grafana.app:get"},
			group:            "folder.grafana.app",
			resource:         "folders",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Non-allowlisted wildcard does not match (group/resource:*)",
			tokenPermissions: []string{"*.grafana.app/datasources:*"},
			group:            "prometheus.datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Non-allowlisted wildcard does not match (group:*)",
			tokenPermissions: []string{"*.grafana.app:*"},
			group:            "folder.grafana.app",
			resource:         "folders",
			verb:             "get",
			want:             false,
		},
		{
			name:             "Exact match still works: folder.grafana.app/folders:* allows get",
			tokenPermissions: []string{"folder.grafana.app/folders:*"},
			group:            "folder.grafana.app",
			resource:         "folders",
			verb:             "get",
			want:             true,
		},
		{
			name:             "Wildcard group-only form allows prometheus.datasource.grafana.app for get",
			tokenPermissions: []string{"*.datasource.grafana.app:get"},
			group:            "prometheus.datasource.grafana.app",
			resource:         "datasources",
			verb:             "get",
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasPermissionInToken(tt.tokenPermissions, tt.group, tt.resource, tt.verb)
			require.Equal(t, tt.want, got)
		})
	}
}
