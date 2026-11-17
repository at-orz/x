package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/at-orz/x/auth"
)

// Revalidate exchanges the session's refresh token at the provider, which asks the provider whether the
// account is still good without anything happening in the browser. Sending the browser to the provider
// once an hour instead would reload the page and cut every open connection with it.
func (p *Provider) Revalidate(ctx context.Context, rec auth.Record) (auth.Record, error) {
	cfg, ok := p.config()
	if !ok {
		return rec, errors.New("the provider is not configured")
	}
	var st refreshState
	if err := json.Unmarshal(rec.State, &st); err != nil || st.RefreshToken == "" {
		// Nothing to present, and nothing will be: this session cannot be revalidated, ever.
		return rec, fmt.Errorf("%w: the session record holds no refresh token", auth.ErrEnded)
	}
	doc, err := p.discover(ctx, cfg.Issuer)
	if err != nil {
		return rec, err
	}
	tr, err := p.postToken(ctx, cfg, doc, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {st.RefreshToken},
	})
	if err != nil {
		var te *tokenError
		if errors.As(err, &te) && te.refused() {
			// The account was disabled, or the token revoked or expired.
			return rec, fmt.Errorf("%w: %w", auth.ErrEnded, err)
		}
		return rec, err
	}
	// An ID token is optional in a refresh response, and when there is one it has to still be about the
	// same person: OIDC Core §12.2 forbids a changed sub, and a provider that hands one over anyway would
	// silently move a live session to another account. The nonce is not checked, since a refresh has none.
	if tr.IDToken != "" {
		tok, err := parseIDToken(tr.IDToken)
		if err != nil {
			return rec, err
		}
		if err := tok.validateRefreshed(cfg, doc.Issuer, rec.Subject); err != nil {
			p.m.Log().Error("the id_token of a refresh does not match the session, ending it",
				"provider", p.name, "subject", rec.Subject, "err", err)
			return rec, fmt.Errorf("%w: %w", auth.ErrEnded, err)
		}
		claims, err := json.Marshal(tok.all)
		if err != nil {
			return rec, err
		}
		rec.Claims = claims
	}
	// A provider that rotates the refresh token sends the new one, which replaces the old; one that does
	// not omits the field, and the token in hand stays valid. Overwriting with an empty string would end
	// the session at the next exchange.
	if tr.RefreshToken != "" {
		state, err := json.Marshal(refreshState{RefreshToken: tr.RefreshToken})
		if err != nil {
			return rec, err
		}
		rec.State = state
	}
	return rec, nil
}
