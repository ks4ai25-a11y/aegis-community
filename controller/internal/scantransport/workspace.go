// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source/scanevidence"
	"io"
	"net/http"
)

func (s *Server) workspace(w http.ResponseWriter, r *http.Request, worker scannerauth.Worker) {
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		failure(w, 400, "INVALID_WORKER_REQUEST")
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, 8192))
	if e != nil {
		failure(w, 400, "INVALID_WORKER_REQUEST")
		return
	}
	in, e := scanevidence.DecodeWorkspaceSubmission(b)
	if e != nil || in.Schema != "1.0" || !jobPattern.MatchString(in.Job) || !hashPattern.MatchString(in.Request) || !tokenPattern.MatchString(in.Token) {
		failure(w, 400, "INVALID_WORKER_REQUEST")
		return
	}
	j, e := s.Q.Get(worker.Owner, in.Job)
	if e != nil {
		queueError(w, e)
		return
	}
	if j.RequestDigest != in.Request {
		failure(w, 409, "SCAN_IDENTITY_CONFLICT")
		return
	}
	record, e := s.Q.ReserveWorkspace(scanqueue.Lease{Job: j, Worker: worker.ID, Token: in.Token}, in.Plan)
	if e != nil {
		queueError(w, e)
		return
	}
	reply(w, 200, map[string]any{"state": "reserved", "record": record})
}
