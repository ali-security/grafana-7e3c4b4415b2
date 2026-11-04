package libraryelements

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/libraryelements/model"
	"github.com/grafana/grafana/pkg/services/user"
)

// Seal: CVE-2026-81842 — with libraryPanelRBAC enabled, moving a library element into
// another folder requires library.panels:create on the destination folder.
func TestHandleFolderIDPatches_LibraryPanelRBACDestinationFolder(t *testing.T) {
	features := featuremgmt.WithFeatures(featuremgmt.FlagLibraryPanelRBAC)
	folders := foldertest.NewFakeService()
	folders.ExpectedFolder = &folder.Folder{ID: 2, UID: "dest-uid", OrgID: 1}
	svc := &LibraryElementService{features: features, folderService: folders, AccessControl: acimpl.ProvideAccessControl(features)}

	signedIn := func(perms map[string][]string) *user.SignedInUser {
		return &user.SignedInUser{OrgID: 1, Permissions: map[int64]map[string][]string{1: perms}}
	}

	for _, tc := range []struct {
		name     string
		from, to int64
		perms    map[string][]string
		wantErr  error
	}{
		{name: "move allowed with create on destination", from: 1, to: 2, perms: map[string][]string{ActionLibraryPanelsCreate: {"folders:uid:dest-uid"}}},
		{name: "move denied with create on another folder only", from: 1, to: 2, perms: map[string][]string{ActionLibraryPanelsCreate: {"folders:uid:other"}}, wantErr: dashboards.ErrFolderAccessDenied},
		{name: "move denied without permissions", from: 1, to: 2, perms: map[string][]string{}, wantErr: dashboards.ErrFolderAccessDenied},
		{name: "move to general allowed with create on general", from: 1, to: 0, perms: map[string][]string{ActionLibraryPanelsCreate: {"folders:uid:general"}}},
		{name: "move to general denied without it", from: 1, to: 0, perms: map[string][]string{ActionLibraryPanelsCreate: {"folders:uid:dest-uid"}}, wantErr: dashboards.ErrFolderAccessDenied},
		{name: "no move is not affected", from: 1, to: -1, perms: map[string][]string{}},
		{name: "same folder is not affected", from: 1, to: 1, perms: map[string][]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			elem := &model.LibraryElement{}
			err := svc.handleFolderIDPatches(context.Background(), elem, tc.from, tc.to, signedIn(tc.perms))
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
