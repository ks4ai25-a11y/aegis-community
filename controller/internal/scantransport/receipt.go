// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source/scanevidence"
	"io"
	"net/http"
)

func (s *Server) receipt(w http.ResponseWriter, r *http.Request, worker scannerauth.Worker) {
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		failure(w, 400, "INVALID_WORKER_REQUEST")
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, scanevidence.MaxSubmission))
	if e != nil {
		failure(w, 400, "INVALID_WORKER_REQUEST")
		return
	}
	in, e := scanevidence.DecodeSubmission(b)
	if e != nil {
		failure(w, 400, "INVALID_WORKER_REQUEST")
		return
	}
	job, e := s.Q.Get(worker.Owner, in.Job)
	if e != nil {
		queueError(w, e)
		return
	}
	if job.RequestDigest != in.Request {
		failure(w, 409, "SCAN_IDENTITY_CONFLICT")
		return
	}
	stored, e := s.Q.RecordReceipt(scanqueue.Lease{Job: job, Worker: worker.ID, Token: in.Token}, in.Execution)
	if e != nil {
		queueError(w, e)
		return
	}
	reply(w, 200, map[string]any{"schema_version": "1.0", "job_id": job.ID, "request_digest": job.RequestDigest, "tool_id": stored.Document.Execution.Tool, "receipt_digest": stored.Digest, "state": "accepted", "cleanup_required": true})
}
