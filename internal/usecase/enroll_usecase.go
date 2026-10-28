package usecase

import (
	"context"
	"errors"
	"fmt"
)

var ErrAlreadyEnrolled = errors.New("host already has a token (use --force to re-enroll)")

type Enroll struct {
	Host    HostInspector
	Central Central
	Creds   CredentialStore
}

func (e *Enroll) Run(ctx context.Context, enrollToken string, force bool) error {
	if enrollToken == "" {
		return errors.New("enroll token is empty")
	}
	if e.Creds.HostToken() != "" && !force {
		return ErrAlreadyEnrolled
	}
	tok, err := e.Central.Enroll(ctx, enrollToken, e.Host.Inspect(ctx))
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if tok == "" {
		return errors.New("enroll: central returned empty host token")
	}
	if err := e.Creds.SaveHostToken(tok); err != nil {
		return fmt.Errorf("save host token: %w", err)
	}
	return nil
}
