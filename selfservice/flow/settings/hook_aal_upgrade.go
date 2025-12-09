// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"net/http"

	"github.com/tidwall/gjson"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

type (
	aalUpgradeHookDependencies interface {
		session.ManagementProvider
		x.LoggingProvider
	}

	AALUpgradeHook struct {
		d aalUpgradeHookDependencies
	}
)

func NewAALUpgradeHook(d aalUpgradeHookDependencies) *AALUpgradeHook {
	return &AALUpgradeHook{d: d}
}

func (e *AALUpgradeHook) ExecuteSettingsPostPersistHook(w http.ResponseWriter, r *http.Request, a *Flow, i *identity.Identity, s *session.Session) error {
	if a == nil || s == nil || i == nil {
		return nil
	}

	log := e.d.Logger().WithRequest(r).
		WithField("flow_id", a.ID).
		WithField("identity_id", i.ID).
		WithField("session_id", s.ID).
		WithField("session_aal", s.AuthenticatorAssuranceLevel)

	// This hook is only registered for profile flows, but we verify as a safeguard.
	if activeStr := string(a.Active); activeStr != "" && activeStr != "profile" {
		log.WithField("active_method", activeStr).Debug("AAL upgrade hook skipped: non-profile flow")
		return nil
	}

	// Require phone_number to be present in identity traits.
	phoneNumber := gjson.GetBytes(i.Traits, "phone_number").String()
	if phoneNumber == "" {
		log.Debug("AAL upgrade hook skipped: phone_number missing from traits")
		return nil
	}

	// Skip if session already has code method recorded.
	// Note: We don't skip if session is already at AAL2 via other methods (e.g., TOTP),
	// as we want to record all available authentication methods in the session.
	if s.AuthenticatedVia(identity.CredentialsTypeCodeAuth) {
		log.Debug("AAL upgrade hook skipped: code method already recorded in session")
		return nil
	}

	// Add code authentication method to session.
	// This will upgrade AAL to aal2 if not already there, or record the method if already at aal2.
	if err := e.d.SessionManager().SessionAddAuthenticationMethods(
		r.Context(),
		s.ID,
		session.AuthenticationMethod{
			Method: identity.CredentialsTypeCodeAuth,
			AAL:    identity.AuthenticatorAssuranceLevel2,
		},
	); err != nil {
		log.WithError(err).Error("Failed to add code authentication method to session after phone number update")
		return err
	}

	log.WithField("phone_number", phoneNumber).Info("Successfully added code authentication method to session after phone number update")
	return nil
}
