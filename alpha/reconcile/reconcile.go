// SPDX-License-Identifier: BUSL-1.1
// Package reconcile performs one independent cleanup release (ADR 057): read
// complete retained membership, hold the original workspace registry empty
// under its approved namespace, observe every required allocation absent on
// the original engine, and only then ask the controller to release.
package reconcile

import (
	"aegis.local/alpha/engineobserve"
	"aegis.local/source/scanevidence"
	"context"
	"errors"
)

var ErrUnreleased = errors.New("scanner cleanup not released")

type Controller interface {
	Snapshot(ctx context.Context, job, generation string) (scanevidence.ReconciliationSnapshot, error)
	Confirm(ctx context.Context, s scanevidence.ReconciliationSnapshot, absent []scanevidence.CleanupAbsence) (scanevidence.CleanupConfirmation, error)
}

type Observer interface {
	VerifyAbsent(ctx context.Context, targets []engineobserve.Target) error
}

// Barrier holds the registry empty for the duration of work; in production it
// is workspace.WithBoundEmptyRegistry.
type Barrier func(ctx context.Context, path, namespace string, work func() error) error

type Release struct {
	Controller Controller
	Observer   Observer
	Barrier    Barrier
	Registry   string
	Namespace  string
	// Required derives the absences to observe; nil uses
	// scanevidence.RequiredAbsences, which tests replace.
	Required func(scanevidence.ReconciliationMembership) ([]scanevidence.CleanupAbsence, error)
}

func (r Release) Run(ctx context.Context, job, generation string) (scanevidence.CleanupConfirmation, error) {
	if r.Controller == nil || r.Observer == nil || r.Barrier == nil || r.Registry == "" || r.Namespace == "" {
		return scanevidence.CleanupConfirmation{}, ErrUnreleased
	}
	var out scanevidence.CleanupConfirmation
	err := r.Barrier(ctx, r.Registry, r.Namespace, func() error {
		s, err := r.Controller.Snapshot(ctx, job, generation)
		if err != nil {
			return err
		}
		if s.Membership.Binding.Document.Namespace != r.Namespace {
			return ErrUnreleased
		}
		required := r.Required
		if required == nil {
			required = scanevidence.RequiredAbsences
		}
		absent, err := required(s.Membership)
		if err != nil {
			return ErrUnreleased
		}
		if len(absent) > 0 {
			targets := make([]engineobserve.Target, 0, len(absent))
			for _, a := range absent {
				targets = append(targets, engineobserve.Target{Name: a.Container, ID: a.EngineID})
			}
			if err = r.Observer.VerifyAbsent(ctx, targets); err != nil {
				return ErrUnreleased
			}
		}
		out, err = r.Controller.Confirm(ctx, s, absent)
		return err
	})
	if err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	return out, nil
}
