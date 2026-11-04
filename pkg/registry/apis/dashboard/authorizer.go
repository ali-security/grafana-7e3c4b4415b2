package dashboard

import (
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/infra/log"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/dashboards"
)

// GetAuthorizer retains the v11.6.0 exported signature for compatibility.
// dashboardService and l are unused; user authorization happens in storage (CVE-2025-3260).
func GetAuthorizer(_ dashboards.DashboardService, _ log.Logger) authorizer.Authorizer {
	return grafanaauthorizer.NewServiceAuthorizer()
}
