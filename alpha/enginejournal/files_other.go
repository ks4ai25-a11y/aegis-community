// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !darwin

package enginejournal

type privateRoot struct{}

func (p *privateRoot) close()                              {}
func (p *privateRoot) newDir(string) (*privateRoot, error) { return nil, ErrJournal }
func (p *privateRoot) write(string, []byte) error          { return ErrJournal }
func Open(string, string) (*Journal, error)                { return nil, ErrJournal }
func ReadObservation(string, string) (Observation, error)  { return Observation{}, ErrJournal }

func OpenExisting(string, string) (*Journal, error) { return nil, ErrJournal }

func InitializeEmpty(string, string) (Observation, error) { return Observation{}, ErrJournal }
