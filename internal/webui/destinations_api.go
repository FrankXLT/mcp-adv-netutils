package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

type pinnedScanResult struct {
	Destination store.SavedDestination `json:"destination"`
	Outcome     *dispatch.Outcome      `json:"outcome,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

const maxPinnedScanConcurrency = 4

func (h *studioHandler) handleDestinations(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost) || !h.requireUnlocked(w, r) {
		return
	}
	if !h.requireDispatcher(w) {
		return
	}
	if r.Method == http.MethodGet {
		res, err := h.dispatcher.ManageSavedDestinations(r.Context(), dispatch.DestinationParams{Action: "list"})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"destinations": nonNilDestinations(res.Items)})
		return
	}
	h.saveDestinationFromRequest(w, r, "")
}

func (h *studioHandler) handleDestinationByID(w http.ResponseWriter, r *http.Request, rest string) {
	if strings.HasSuffix(rest, "/run") {
		id := strings.TrimSuffix(rest, "/run")
		if id == "" || strings.Contains(id, "/") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "destination not found"})
			return
		}
		h.handleDestinationRun(w, r, id)
		return
	}
	if rest == "" || strings.Contains(rest, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "destination not found"})
		return
	}
	if !requireMethod(w, r, http.MethodPut, http.MethodDelete) || !h.requireUnlocked(w, r) {
		return
	}
	if !h.requireDispatcher(w) {
		return
	}
	if r.Method == http.MethodPut {
		h.saveDestinationFromRequest(w, r, rest)
		return
	}
	res, err := h.dispatcher.ManageSavedDestinations(r.Context(), dispatch.DestinationParams{Action: "delete", ID: rest})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": rest, "destinations": nonNilDestinations(res.Items)})
}

func (h *studioHandler) saveDestinationFromRequest(w http.ResponseWriter, r *http.Request, pathID string) {
	raw, status, msg := readLimitedBody(w, r.Body, maxRunBodySize)
	if status != 0 {
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must not be empty"})
		return
	}
	var params dispatch.DestinationParams
	if err := json.Unmarshal(raw, &params); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawFields); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if rawMAC, ok := rawFields["mac"]; ok {
		var macVal string
		if err := json.Unmarshal(rawMAC, &macVal); err == nil && strings.TrimSpace(macVal) == "" {
			params.ClearMAC = true
		}
	}
	if pathID != "" {
		params.ID = pathID
	}
	params.Action = "save"
	res, err := h.dispatcher.ManageSavedDestinations(r.Context(), params)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": res.Item, "destinations": nonNilDestinations(res.Items)})
}

func (h *studioHandler) handleDestinationRun(w http.ResponseWriter, r *http.Request, id string) {
	if !requireMethod(w, r, http.MethodPost) || !h.requireUnlocked(w, r) {
		return
	}
	if !h.requireDispatcher(w) {
		return
	}
	style, ok := decodeOptionalStyle(w, r)
	if !ok {
		return
	}
	out, err := h.dispatcher.RunSavedDestination(r.Context(), id, style, "webui", true)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *studioHandler) handleScanPinned(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !h.requireUnlocked(w, r) {
		return
	}
	if !h.requireDispatcher(w) {
		return
	}
	style, ok := decodeOptionalStyle(w, r)
	if !ok {
		return
	}
	listRes, err := h.dispatcher.ManageSavedDestinations(r.Context(), dispatch.DestinationParams{Action: "list"})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	var pinned []store.SavedDestination
	for i := range listRes.Items {
		if listRes.Items[i].Pinned {
			pinned = append(pinned, listRes.Items[i])
		}
	}
	if len(pinned) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []pinnedScanResult{}})
		return
	}
	results := h.runPinnedDestinations(r.Context(), pinned, style)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(results), "results": results})
}

func (h *studioHandler) runPinnedDestinations(ctx context.Context, pinned []store.SavedDestination, style string) []pinnedScanResult {
	results := make([]pinnedScanResult, len(pinned))
	sem := make(chan struct{}, min(maxPinnedScanConcurrency, len(pinned)))
	var wg sync.WaitGroup
	for i := range pinned {
		dst := pinned[i]
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = pinnedScanResult{Destination: dst, Error: ctx.Err().Error()}
			continue
		}
		wg.Add(1)
		go func(idx int, d store.SavedDestination) {
			defer wg.Done()
			defer func() { <-sem }()
			out, runErr := h.dispatcher.RunSavedDestination(ctx, d.ID, style, "webui_pinned", true)
			res := pinnedScanResult{Destination: d, Outcome: out}
			if runErr != nil {
				res.Error = runErr.Error()
			}
			results[idx] = res
		}(i, dst)
	}
	wg.Wait()
	return results
}

func decodeOptionalStyle(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		Style string `json:"style"`
	}
	if status, msg := decodeOptionalJSON(w, r.Body, maxRunBodySize, &body); status != 0 {
		writeJSON(w, status, map[string]string{"error": msg})
		return "", false
	}
	style := strings.TrimSpace(body.Style)
	if style == "" {
		style = ascii.StyleJSON
	}
	return style, true
}

func (h *studioHandler) requireDispatcher(w http.ResponseWriter) bool {
	if h.dispatcher != nil {
		return true
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dispatcher not configured"})
	return false
}

func nonNilDestinations(items []store.SavedDestination) []store.SavedDestination {
	if items == nil {
		return []store.SavedDestination{}
	}
	return items
}
