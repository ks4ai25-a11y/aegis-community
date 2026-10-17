// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package enginejournal

import "aegis.local/source/scanevidence"

type privateRoot struct{}

func (p *privateRoot) close()                              {}
func (p *privateRoot) newDir(string) (*privateRoot, error) { return nil, ErrJournal }
func (p *privateRoot) write(string, []byte) error          { return ErrJournal }
func Open(string, string) (*Journal, error)                { return nil, ErrJournal }
func ReadObservation(string, string) (Observation, error)  { return Observation{}, ErrJournal }

func OpenExisting(string, string) (*Journal, error) { return nil, ErrJournal }

func InitializeEmpty(string, string) (Observation, error) { return Observation{}, ErrJournal }

func (j *Journal) SealQuarantine() (QuarantineState, error) { return QuarantineState{}, ErrQuarantine }
func (j *Journal) RecordActivation() (QuarantineState, error) {
	return QuarantineState{}, ErrQuarantine
}
func (j *Journal) finishedLocked(string)           {}
func (j *Journal) Resume(string) (*Attempt, error) { return nil, ErrQuarantine }
func (j *Journal) RecordRepair(string, string, string, string, string) error {
	return ErrQuarantine
}
func (j *Journal) PendingOperation(string) (string, *scanevidence.MutationIntent, error) {
	return "", nil, ErrQuarantine
}
func ReadEvidence(string, string, string) (Evidence, error) { return Evidence{}, ErrJournal }
func (j *Journal) SettleReleased(string, scanevidence.CleanupConfirmation) error {
	return ErrQuarantine
}
