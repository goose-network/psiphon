// notice.go: the process-global tunnel-core notice hub.
//
// tunnel-core's notice writer is a global singleton (psiphon.SetNoticeWriter
// refuses to replace a non-default writer), and the plugin may run several
// providers and controllers in one process. The hub is installed exactly once
// — with sync.Once — and fans each decoded notice out to every subscribed
// provider, which filters for the events it cares about.
//
// Diagnostics are routed to the hub rather than to notice files: the base
// config sets EmitDiagnosticNotices and leaves UseNoticeFiles unset, so
// diagnostic notices — including RemoteServerListResourceDownloaded, the
// signal that the signed server list landed in the datastore — reach the
// in-process receiver and can prompt an immediate engine re-poll (the web UI
// sees the new servers seconds after the download, not at the next periodic
// poll).
package psiphon

import (
	"encoding/json"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// notice is the decoded form of a tunnel-core notice event. Only the fields
// the hub consumers read are surfaced.
type notice struct {
	Type string         `json:"noticeType"`
	Data map[string]any `json:"data"`
}

// noticeHub fans tunnel-core notices out to subscribed callbacks.
type noticeHub struct {
	mu   sync.Mutex
	next int64
	subs map[int64]func(notice)
}

var hub = &noticeHub{subs: map[int64]func(notice){}}

var hubInstallOnce sync.Once

// installNoticeHub routes tunnel-core's global notice stream into the hub.
// Safe to call from every provider; the writer is set at most once per
// process. An embedder that already claimed the writer keeps its notices —
// SetNoticeWriter's error is swallowed and the hub simply stays empty.
func installNoticeHub() {
	hubInstallOnce.Do(func() {
		receiver := psiphon.NewNoticeReceiver(func(event []byte) {
			hub.dispatch(event)
		})
		_ = psiphon.SetNoticeWriter(receiver)
	})
}

// subscribe registers fn for every subsequent notice and returns the
// unsubscribe function.
func (h *noticeHub) subscribe(fn func(notice)) func() {
	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = fn
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.subs, id)
		h.mu.Unlock()
	}
}

// dispatch decodes one raw notice event and fans it out. Undecodable events
// are dropped: a malformed notice must not take the tunnel down.
func (h *noticeHub) dispatch(event []byte) {
	var n notice
	if err := json.Unmarshal(event, &n); err != nil || n.Type == "" {
		return
	}
	h.mu.Lock()
	subs := make([]func(notice), 0, len(h.subs))
	for _, fn := range h.subs {
		subs = append(subs, fn)
	}
	h.mu.Unlock()
	for _, fn := range subs {
		fn(n)
	}
}
