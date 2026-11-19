package leash

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// runRefusal is the answer to an item.run the item's settings refuse
// (§10.11): way_not_allowed {ways}, program_not_allowed, or
// env_not_allowed {names}.
func runRefusal(j itemspec.RunJudgement, w *itemspec.ItemWays) error {
	switch j.Refusal {
	case "way_not_allowed":
		return wayNotAllowed(w)
	case "env_not_allowed":
		return &vault.HandlerError{Code: "env_not_allowed", Body: strictjson.NewBuilder().Raw("names", itemspec.StrList(j.Names)).Bytes()}
	}
	return &vault.HandlerError{Code: j.Refusal}
}

// runNote is what a referred item.run was decided under, kept with the
// held request (vault.Session.NoteApproval) and read back when an app
// approves it: the settings' version, and the pin situation the approval
// showed (its flags, and the previous pin with program_changed).
type runNote struct {
	Version        uint64   `json:"version"`
	Flags          []string `json:"flags,omitempty"`
	PreviousSHA256 string   `json:"previous_sha256,omitempty"`
	PreviousPath   string   `json:"previous_path,omitempty"`
}

func noteOf(j itemspec.RunJudgement, version uint64) runNote {
	return runNote{Version: version, Flags: j.Flags, PreviousSHA256: j.PreviousSHA256, PreviousPath: j.PreviousPath}
}

// shows reports whether the approval n was held with showed what j would
// show now: the same flags and the same previous pin.
func (n runNote) shows(j itemspec.RunJudgement) bool {
	if len(n.Flags) != len(j.Flags) || n.PreviousSHA256 != j.PreviousSHA256 || n.PreviousPath != j.PreviousPath {
		return false
	}
	for i := range n.Flags {
		if n.Flags[i] != j.Flags[i] {
			return false
		}
	}
	return true
}

func (n runNote) approval() vault.Approval {
	raw, _ := json.Marshal(n)
	return vault.Approval{Flags: n.Flags, PreviousSHA256: n.PreviousSHA256, PreviousPath: n.PreviousPath, Note: raw}
}

// holdRun sets what a referred item.run is held with: its flags, the
// previous pin, and the note.
func holdRun(s *vault.Session, j itemspec.RunJudgement, version uint64) {
	a := noteOf(j, version).approval()
	if len(a.Flags) > 0 {
		s.FlagApproval(a.Flags)
	}
	if a.PreviousSHA256 != "" {
		s.ApprovalPrevious(a.PreviousSHA256, a.PreviousPath)
	}
	s.NoteApproval(a.Note)
}

// itemRun answers an item.run (§10.11) once the policy allowed it, or an
// app approved it. The settings are judged again: a run they now refuse
// gets that refusal, never the value. One allowed at once must still
// need no app (else forbidden: fail secure). For an approved one:
//   - the run's program matches the recorded pin (or the item is
//     unbound): the member approved this run, which needs no new pin; it
//     stands, whatever changed meanwhile;
//   - the run would record a pin, and the approval showed the same flags
//     and previous pin: it stands, and records it (settings unchanged
//     since the decision always come here);
//   - the run would record a pin against another pin than the approval
//     showed (another approval recorded one meanwhile): it is referred
//     again as a new approval, a new referral, refused forbidden past the
//     cap; the value is never sent on the old one.
//
// The note's version is what the run was decided under; any change since
// is covered by judging again, so it is not compared.
//
// An approved run flagged program_unrecorded or program_changed records
// its own sha256 and program as the matched entry's pin, raising the
// settings' version, announced and audited as leash.item.changed: only
// from an approval, never from the agent's request alone.
func (f *Feature) itemRun(s *vault.Session, agent string, rules []itemspec.AgentRule, r *Request) (json.RawMessage, error) {
	w, ok := f.items.AgentWays(agent, rules, r.ItemID)
	if !ok {
		return nil, errNotFound
	}
	j := itemspec.JudgeRun(w, r.Run)
	if j.Refusal != "" {
		return nil, runRefusal(j, w)
	}
	if !s.Approved() {
		if j.Refer {
			return nil, errForbidden
		}
	} else {
		var n runNote
		if err := json.Unmarshal(s.HeldNote(), &n); err != nil {
			return nil, errForbidden // a held run without its note: never run unseen
		}
		if j.RecordsPin() && !n.shows(j) {
			return nil, f.referAgain(s, agent, noteOf(j, w.Version).approval())
		}
		if j.RecordsPin() {
			// The member's approval records the pin even if the field is
			// then gone (the answer below is not_found).
			if err := f.recordPin(s, agent, rules, r, w, j); err != nil {
				return nil, err
			}
		}
	}
	value, ok := f.items.AgentFieldValue(agent, rules, r.ItemID, r.FieldID)
	if !ok {
		return nil, errNotFound
	}
	f.note(s, agent, f.agent(s, agent), vault.Activity{Kind: KindRun, Ref: r.ItemID, Feed: true})
	return strictjson.NewBuilder().String("item_id", r.ItemID).String("field_id", r.FieldID).String("value", value).Bytes(), nil
}

// recordPin records the approved run's sha256 and program as the matched
// entry's pin (§10.11, 0.85.3).
func (f *Feature) recordPin(s *vault.Session, agent string, rules []itemspec.AgentRule, r *Request, w *itemspec.ItemWays, j itemspec.RunJudgement) error {
	next, ok := itemspec.WithPin(w, j.Entry.Program, r.Run.SHA256, r.Run.Program)
	if !ok {
		return errForbidden
	}
	next.Version = w.Version + 1
	next.Updated = s.Now().UTC().Truncate(time.Millisecond)
	if !f.items.AgentSetWays(agent, rules, r.ItemID, next) {
		return errNotFound
	}
	s.SyncEvent("leash.item.changed", strictjson.NewBuilder().String("agent_id", agent).String("item_id", r.ItemID).
		Uint("version", next.Version).Bytes())
	s.Record(vault.Activity{Kind: "leash.item.changed", DeviceID: agent, Ref: r.ItemID, Audit: true})
	return nil
}

// referAgain refers an approved agent request again as a new approval
// held with a (vault.ReferAgain). It is a new referral: past the cap it
// is throttled as in AgentDecision (referrals_limited once, a throttled
// refusal counted) and answered forbidden. It is counted before the
// runtime holds it; should the hold be refused (limit), the count errs
// towards the cap.
func (f *Feature) referAgain(s *vault.Session, agent string, a vault.Approval) error {
	st := f.agent(s, agent)
	if st.Referred >= MaxReferralsPerHour {
		if !st.RefLimited {
			st.RefLimited = true
			s.Record(vault.Activity{Kind: "leash.referrals_limited", DeviceID: agent, Audit: true, Feed: true, Priority: "high"})
		}
		f.refuse(s, agent, st, KindThrottled, ScopeItems)
		return errForbidden
	}
	st.Referred++
	return vault.ReferAgain(a)
}
