package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type queueActionRequest struct {
	Reason   string `json:"reason"`
	WorkerID string `json:"worker_id"`
}

// handleGetQueueObservability returns a compact operational queue snapshot.
func (s *Server) handleGetQueueObservability(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.queueMgr.GetObservabilitySnapshot()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, snapshot)
}

// handleRequeueMessage resets a message for another delivery attempt.
func (s *Server) handleRequeueMessage(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req queueActionRequest
	if err := decodeOptionalQueueActionRequest(r, &req); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.queueMgr.RequeueMessage(id, req.Reason); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]string{
		"status":     "success",
		"message_id": id,
		"action":     "requeued",
	})
}

// handleHoldMessage moves a message to the hold queue.
func (s *Server) handleHoldMessage(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req queueActionRequest
	if err := decodeOptionalQueueActionRequest(r, &req); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.queueMgr.HoldMessage(id, req.Reason); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]string{
		"status":     "success",
		"message_id": id,
		"action":     "held",
	})
}

// handleReleaseMessageClaim clears a backend worker claim from a message.
func (s *Server) handleReleaseMessageClaim(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req queueActionRequest
	if err := decodeOptionalQueueActionRequest(r, &req); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.queueMgr.ReleaseMessageClaim(id, req.WorkerID); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]string{
		"status":     "success",
		"message_id": id,
		"action":     "claim_released",
	})
}

func decodeOptionalQueueActionRequest(r *http.Request, req *queueActionRequest) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()

	if strings.TrimSpace(r.Header.Get("Content-Length")) == "0" {
		return nil
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(req); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}
