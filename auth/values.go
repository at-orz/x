package auth

import (
	"context"
	"errors"
	"fmt"
	"maps"
)

// valueTries bounds how often a change of a value is retried after losing to a concurrent write.
const valueTries = 3

// SetValue sets one of the host's values of a live session. It takes effect on the session's next
// request, on every instance, and reports ErrNotFound for a session that has ended.
func (m *Manager) SetValue(ctx context.Context, sid, key, value string) error {
	return m.changeValues(ctx, sid, func(v map[string]string) map[string]string {
		if v == nil {
			v = map[string]string{}
		}
		v[key] = value
		return v
	})
}

// DeleteValue removes one of the host's values of a live session, like SetValue.
func (m *Manager) DeleteValue(ctx context.Context, sid, key string) error {
	return m.changeValues(ctx, sid, func(v map[string]string) map[string]string {
		delete(v, key)
		return v
	})
}

// changeValues is a read-modify-write of the record. A write that loses to a concurrent one — a
// revalidation on another instance, say — is retried from the read, so a value is never lost silently.
func (m *Manager) changeValues(ctx context.Context, sid string, change func(map[string]string) map[string]string) error {
	var err error
	for range valueTries {
		var rec Record
		rec, err = m.store.Get(ctx, sid)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				m.live.drop(sid)
			}
			return err
		}
		// A copy, because the map read may be the very one a cache or a request holds.
		rec.Values = change(maps.Clone(rec.Values))
		err = m.store.Touch(ctx, sid, rec)
		switch {
		case err == nil:
			m.remember(sid, rec)
			return nil
		case errors.Is(err, ErrNotFound):
			m.live.drop(sid)
			return err
		case !errors.Is(err, ErrConflict):
			return err
		}
	}
	return fmt.Errorf("changing a value of session %q lost %d times in a row: %w", sid, valueTries, err)
}
