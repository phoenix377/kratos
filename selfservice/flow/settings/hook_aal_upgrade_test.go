package settings_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/session"
	"github.com/ory/x/sqlxx"
)

func TestAALUpgradeHook(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	h := settings.NewAALUpgradeHook(reg)

	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/identity.schema.json")

	newSession := func(t *testing.T) *session.Session {
		t.Helper()
		sess := session.NewInactiveSession()
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, sess))
		return sess
	}

	t.Run("case=should upgrade AAL when phone number is present", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings", nil)
		i := &identity.Identity{Traits: []byte(`{"phone_number": "+1234567890"}`)}
		sess := newSession(t)
		f := &settings.Flow{Active: sqlxx.NullString("profile")}

		require.NoError(t, h.ExecuteSettingsPostPersistHook(httptest.NewRecorder(), req, f, i, sess))

		updatedSession, err := reg.SessionPersister().GetSession(ctx, sess.ID, session.ExpandNothing)
		require.NoError(t, err)

		assert.Equal(t, identity.AuthenticatorAssuranceLevel2, updatedSession.AuthenticatorAssuranceLevel)
		require.Len(t, updatedSession.AMR, 1)
		assert.Equal(t, identity.CredentialsTypeCodeAuth, updatedSession.AMR[0].Method)
	})

	t.Run("case=should not upgrade AAL when phone number is missing", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings", nil)
		i := &identity.Identity{Traits: []byte(`{"email": "test@example.com"}`)}
		sess := newSession(t)
		f := &settings.Flow{Active: sqlxx.NullString("profile")}

		require.NoError(t, h.ExecuteSettingsPostPersistHook(httptest.NewRecorder(), req, f, i, sess))

		updatedSession, err := reg.SessionPersister().GetSession(ctx, sess.ID, session.ExpandNothing)
		require.NoError(t, err)

		assert.NotEqual(t, identity.AuthenticatorAssuranceLevel2, updatedSession.AuthenticatorAssuranceLevel)
		assert.Len(t, updatedSession.AMR, 0)
	})

	t.Run("case=should not run for non-profile flow", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings", nil)
		i := &identity.Identity{Traits: []byte(`{"phone_number": "+1234567890"}`)}
		sess := newSession(t)
		f := &settings.Flow{Active: sqlxx.NullString("password")}

		require.NoError(t, h.ExecuteSettingsPostPersistHook(httptest.NewRecorder(), req, f, i, sess))

		updatedSession, err := reg.SessionPersister().GetSession(ctx, sess.ID, session.ExpandNothing)
		require.NoError(t, err)

		assert.NotEqual(t, identity.AuthenticatorAssuranceLevel2, updatedSession.AuthenticatorAssuranceLevel)
		assert.Len(t, updatedSession.AMR, 0)
	})

	t.Run("case=should be idempotent when code already recorded", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings", nil)
		i := &identity.Identity{Traits: []byte(`{"phone_number": "+1234567890"}`)}
		sess := newSession(t)
		sess.CompletedLoginFor(identity.CredentialsTypeCodeAuth, identity.AuthenticatorAssuranceLevel2)
		sess.SetAuthenticatorAssuranceLevel()
		require.NoError(t, reg.SessionPersister().UpsertSession(ctx, sess))

		f := &settings.Flow{Active: sqlxx.NullString("profile")}

		require.NoError(t, h.ExecuteSettingsPostPersistHook(httptest.NewRecorder(), req, f, i, sess))

		updatedSession, err := reg.SessionPersister().GetSession(ctx, sess.ID, session.ExpandNothing)
		require.NoError(t, err)

		assert.Equal(t, identity.AuthenticatorAssuranceLevel2, updatedSession.AuthenticatorAssuranceLevel)
		assert.Len(t, updatedSession.AMR, 1)
		assert.Equal(t, identity.CredentialsTypeCodeAuth, updatedSession.AMR[0].Method)
	})
}
