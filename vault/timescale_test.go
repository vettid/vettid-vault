package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/invite"
)

// The staging time scale in the vault (VAULT-MESSAGING 0.43.0 §11.10.8,
// STAGING-TIME-SCALE §3, §5.5, §5.6): each scaled wait at 24 and at 1,
// the absolute times kept, settings in real units, timers started before
// the move keep their times, and nothing else changes.

func TestScale(t *testing.T) {
	cases := []struct {
		d    time.Duration
		n    uint64
		want time.Duration
	}{
		{24 * time.Hour, 0, 24 * time.Hour},
		{24 * time.Hour, 1, 24 * time.Hour},
		{24 * time.Hour, 24, time.Hour},
		{72 * time.Hour, 24, 3 * time.Hour},
		{7 * 24 * time.Hour, 24, 7 * time.Hour},
		{6 * time.Hour, 24, 15 * time.Minute},
		{time.Hour, 24, 150 * time.Second},
		{30 * 24 * time.Hour, 24, 30 * time.Hour},
		{time.Hour + time.Nanosecond, 24, 151 * time.Second}, // rounded up to a whole second
		{24 * time.Hour, 3600, 24 * time.Second},
		{time.Hour, 86400, time.Second},
		{time.Hour, 1 << 40, time.Second}, // bounded to MaxTimeScale
		{0, 24, 0},
	}
	for _, c := range cases {
		if got := Scale(c.d, c.n); got != c.want {
			t.Errorf("Scale(%v, %d) = %v, want %v", c.d, c.n, got, c.want)
		}
	}
	for _, n := range []uint64{0, 1} {
		o := Options{TimeScale: n}
		if o.timeScale() != 1 || o.scale(PendingUnlinkTTL) != PendingUnlinkTTL {
			t.Fatalf("scale %d is not real time", n)
		}
	}
}

// S1: the owner check's deadline is the check plus the interval divided
// by the scale; the setting and every report of it stay in real units; a
// shorter interval moves the deadline as scaled.
func TestTimeScaleOwnerCheck(t *testing.T) {
	for _, scale := range []uint64{1, 24} {
		f := newOCFixture(t)
		f.m.opt.TimeScale = scale
		now := time.Now().UTC().Truncate(time.Millisecond)
		f.m.mu.Lock()
		info := f.m.ownerCheckPassed(nil, false, "", now)
		f.m.mu.Unlock()
		if want := now.Add(24 * time.Hour / time.Duration(scale)); !info.Deadline.Equal(want) || !f.m.st.OwnerCheck.Deadline.Equal(want) {
			t.Fatalf("scale %d: deadline %v, want %v", scale, info.Deadline, want)
		}
		if info.Interval != 24*time.Hour {
			t.Fatalf("scale %d: interval reported %v", scale, info.Interval)
		}
		st := f.status(t, f.app)
		if n, _ := st.Uint("interval_seconds", 0, 1<<40); n != 86400 {
			t.Fatalf("scale %d: vault.status interval_seconds %d", scale, n)
		}
		// The shortest setting, 1 hour: 2.5 minutes at 24.
		prev := f.m.st.Settings
		f.m.st.Settings.OwnerCheckSeconds = 3600
		f.m.mu.Lock()
		f.m.settingsOwnerCheck(prev, f.m.st.Settings, now)
		f.m.mu.Unlock()
		want := now.Add(time.Hour)
		if scale == 24 {
			want = now.Add(150 * time.Second)
		}
		if !f.m.st.OwnerCheck.Deadline.Equal(want) {
			t.Fatalf("scale %d: after the setting, deadline %v, want %v", scale, f.m.st.OwnerCheck.Deadline, want)
		}
		if o, err := strictjson.ParseObject(f.m.st.Settings.json()); err != nil {
			t.Fatal(err)
		} else if n, _ := o.Uint("owner_check.interval_seconds", 0, 1<<40); n != 3600 {
			t.Fatalf("scale %d: the setting reads %d", scale, n)
		}
		// Due exactly at the scaled deadline.
		f.m.mu.Lock()
		before, at := f.m.ownerCheckState(want.Add(-time.Second)), f.m.ownerCheckState(want)
		f.m.mu.Unlock()
		if before != OwnerCheckOK || at == OwnerCheckOK {
			t.Fatalf("scale %d: %s before, %s at the deadline", scale, before, at)
		}
	}
}

// §5.5: a deadline set under scale 1 is kept when the vault runs a scaled
// release; the first check passed after the move sets a scaled one.
func TestTimeScaleOwnerCheckTransition(t *testing.T) {
	f := newOCFixture(t)
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	f.m.mu.Lock()
	f.m.ownerCheckPassed(nil, false, "", t0)
	f.m.mu.Unlock()
	old := f.m.st.OwnerCheck.Deadline
	if !old.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("deadline at scale 1: %v", old)
	}
	f.m.opt.TimeScale = 24 // the vault now runs a release with the scale
	f.m.mu.Lock()
	f.m.ownerCheckInit(t0.Add(time.Minute))
	f.m.ownerCheckTick(t0.Add(2 * time.Hour))
	state := f.m.ownerCheckState(t0.Add(2 * time.Hour))
	f.m.mu.Unlock()
	if !f.m.st.OwnerCheck.Deadline.Equal(old) || state != OwnerCheckOK {
		t.Fatalf("a deadline set before the move changed: %v %s", f.m.st.OwnerCheck.Deadline, state)
	}
	t1 := t0.Add(3 * time.Hour)
	f.m.mu.Lock()
	f.m.ownerCheckPassed(nil, false, "", t1)
	f.m.mu.Unlock()
	if !f.m.st.OwnerCheck.Deadline.Equal(t1.Add(time.Hour)) {
		t.Fatalf("first check after the move: %v", f.m.st.OwnerCheck.Deadline)
	}
}

// S5, S6: the code's delay and validity, divided; a recovery requested
// before the move keeps its not_before and expires.
func TestTimeScaleRecoveryRequest(t *testing.T) {
	for _, scale := range []uint64{1, 24} {
		r := newRecFixture(t)
		r.opts.TimeScale = scale
		_, rec, _, err := RecoveryRequest(context.Background(), r.params(), recID, RecoveryDelay)
		if err != nil {
			t.Fatal(err)
		}
		d := 24 * time.Hour / time.Duration(scale)
		if !rec.NotBefore.Equal(r.now.Add(d)) || !rec.Expires.Equal(rec.NotBefore.Add(d)) {
			t.Fatalf("scale %d: not_before %v, expires %v (requested %v)", scale, rec.NotBefore, rec.Expires, r.now)
		}
		h, _ := r.header(t)
		if !h.Recovery.NotBefore.Equal(rec.NotBefore) || !h.Recovery.Expires.Equal(rec.Expires) {
			t.Fatalf("scale %d: header %+v", scale, h.Recovery)
		}
	}
	// Transition: requested at scale 1, then the vault runs at 24.
	r := newRecFixture(t)
	code, rec, _, err := RecoveryRequest(context.Background(), r.params(), recID, RecoveryDelay)
	if err != nil {
		t.Fatal(err)
	}
	r.opts.TimeScale = 24
	r.now = r.now.Add(2 * time.Hour)
	if err := RecoveryRegister(context.Background(), r.params(), recID, code, testApp, ok); RecoveryCodeResult(err) != CodeRecoveryEarly {
		t.Fatalf("a code requested before the move became usable at the scaled delay: %v", err)
	}
	if h, _ := r.header(t); !h.Recovery.NotBefore.Equal(rec.NotBefore) || !h.Recovery.Expires.Equal(rec.Expires) {
		t.Fatalf("times changed: %+v", h.Recovery)
	}
}

// S6 after a wait: the recovery stays open for the wait plus the validity,
// whose 24 h are divided; the wait W(k) itself is not. The code was
// requested at scale 1 (the fixture), so its times are kept.
func TestTimeScaleRecoveryValidityAfterWait(t *testing.T) {
	expires := map[uint64]time.Time{}
	for _, scale := range []uint64{1, 24} {
		f := newOpenFixture(t)
		nb := f.storedHeader().Recovery.NotBefore
		f.opts.TimeScale = scale
		f.open(testPIN, "wrong password one")
		_, out := f.open("000000", rPW)
		if out.Code != OpenWrong || out.RetryAt.IsZero() || out.Expires.IsZero() {
			t.Fatalf("scale %d: second wrong: %+v", scale, out)
		}
		if h := f.storedHeader(); h.Recovery == nil || !h.Recovery.NotBefore.Equal(nb) {
			t.Fatalf("scale %d: not_before changed", scale)
		}
		expires[scale] = out.Expires
	}
	if d := expires[1].Sub(expires[24]); d != 23*time.Hour {
		t.Fatalf("validity after a wait: scale 1 %v, scale 24 %v (%v apart)", expires[1], expires[24], d)
	}
}

// S8: the counter's urgent notice after 24 h unreadable, 1 h at 24.
func TestTimeScaleCounterNotice(t *testing.T) {
	for _, scale := range []uint64{1, 24} {
		d := newDevFixture(t)
		d.m.opt.TimeScale = scale
		t0 := time.Now()
		after := 24 * time.Hour / time.Duration(scale)
		d.m.mu.Lock()
		d.m.rec.unavailableSince = t0
		d.m.recoveryHousekeeping(context.Background(), t0.Add(after-time.Second))
		early := !d.m.st.RecoveryCounterNotice.IsZero()
		d.m.recoveryHousekeeping(context.Background(), t0.Add(after))
		raised := !d.m.st.RecoveryCounterNotice.IsZero()
		d.m.mu.Unlock()
		if early || !raised {
			t.Fatalf("scale %d: notice early %v, raised %v", scale, early, raised)
		}
	}
}

// S11: the old phone's held notice is deleted 7 days after the approval,
// 7 hours at 24; a notice held before the move (no Until) keeps 7 days.
func TestTimeScalePendingUnlink(t *testing.T) {
	for _, scale := range []uint64{1, 24} {
		d := newDevFixture(t)
		d.m.opt.TimeScale = scale
		t0 := time.Now().UTC()
		d.m.mu.Lock()
		d.m.holdUnlink(d.devPeer, "t1", 2, t0)
		d.m.mu.Unlock()
		pu := d.m.st.PendingUnlink
		if pu == nil {
			t.Fatal("not held")
		}
		pu.TokenExp = t0.Add(30 * 24 * time.Hour) // the token outlives the notice
		ttl := 7 * 24 * time.Hour / time.Duration(scale)
		if !pu.Until.Equal(pu.At.Add(ttl)) {
			t.Fatalf("scale %d: until %v, at %v", scale, pu.Until, pu.At)
		}
		d.m.mu.Lock()
		d.m.expirePendingUnlink(pu.At.Add(ttl))
		kept := d.m.st.PendingUnlink != nil
		d.m.expirePendingUnlink(pu.At.Add(ttl + time.Second))
		gone := d.m.st.PendingUnlink == nil
		d.m.mu.Unlock()
		if !kept || !gone {
			t.Fatalf("scale %d: kept at its time %v, deleted after %v", scale, kept, gone)
		}
	}
	// Held by a release before the scale: no Until, 7 days from At.
	d := newDevFixture(t)
	d.m.opt.TimeScale = 24
	t0 := time.Now().UTC()
	d.m.st.PendingUnlink = &PendingUnlink{At: t0, TokenExp: t0.Add(30 * 24 * time.Hour), TransferID: "t0"}
	d.m.mu.Lock()
	d.m.expirePendingUnlink(t0.Add(7*24*time.Hour - time.Minute))
	kept := d.m.st.PendingUnlink != nil
	d.m.mu.Unlock()
	if !kept {
		t.Fatal("a notice held before the move lost its 7 days")
	}
}

// S13: a provisional vault's window, 24 h or 1 h, recorded in the header;
// a header from before the scale has the 24 h from created_at.
func TestTimeScaleEnrollWindow(t *testing.T) {
	for _, scale := range []uint64{1, 24} {
		f := newFixture(t)
		o := f.opts
		o.TimeScale = scale
		k, err := MinKDF()
		if err != nil {
			t.Fatal(err)
		}
		m, err := Create(context.Background(), CreateParams{Options: o, UserGUID: "u2", PIN: testPIN, UnlockSecret: testSecret, KDF: k,
			RelayURL: "https://relay.example.org", Provisional: true})
		if err != nil {
			t.Fatal(err)
		}
		h := m.hdr
		if want := h.CreatedAt.Add(24 * time.Hour / time.Duration(scale)); !h.EnrollUntil.Equal(want) || !h.ProvisionalUntil().Equal(want) {
			t.Fatalf("scale %d: enroll_until %v, created %v", scale, h.EnrollUntil, h.CreatedAt)
		}
	}
	old := &Header{CreatedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	if !old.ProvisionalUntil().Equal(old.CreatedAt.Add(24 * time.Hour)) {
		t.Fatal("a header from before the scale")
	}
	// A vault that is not provisional records nothing (no new member).
	if f := newFixture(t); !f.m.hdr.EnrollUntil.IsZero() {
		t.Fatal("enroll_until on a confirmed vault")
	}
}

// vault.status and a transfer bundle carry the scale (§10.2, §11.10.9):
// to the app and desktops, 1 when unset.
func TestTimeScaleReported(t *testing.T) {
	for _, scale := range []uint64{0, 1, 24} {
		f := newOCFixture(t)
		f.m.opt.TimeScale = scale
		want := max(scale, 1)
		for _, td := range []*tdev{f.app, f.desk} {
			r := f.req(t, td, "vault.status", `{}`)
			o, err := strictjson.ParseObject(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := o.Uint("time_scale", 1, MaxTimeScale); err != nil || n != want {
				t.Fatalf("scale %d, %s: vault.status time_scale %d %v", scale, td.peer.Kind, n, err)
			}
		}
		r := f.req(t, f.agent, "vault.status", `{}`)
		if o, _ := strictjson.ParseObject(r.Body); o.Has("time_scale") {
			t.Fatal("an agent is told the time scale")
		}
		claims := map[string][]byte{}
		f.relay.claims = &claims
		for _, kind := range []string{KindApp, KindDesktop} {
			f.m.mu.Lock()
			_, link, err := f.m.createInvite(context.Background(), kind, 10*time.Minute, "dev1", f.m.now())
			f.m.mu.Unlock()
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			q, err := invite.ParseLink(link)
			if err != nil {
				t.Fatal(err)
			}
			b, err := invite.OpenBundle(claims[q.ClaimID], q, f.m.now())
			if err != nil {
				t.Fatal(err)
			}
			if kind == KindApp && b.TimeScale != want || kind != KindApp && b.TimeScale != 0 {
				t.Fatalf("scale %d: %s bundle time_scale %d", scale, kind, b.TimeScale)
			}
		}
	}
}

// Not scaled (§2.2, §3 rule 4): the constants of the waits the spec keeps
// in real time are unchanged, and none of them is computed through the
// scale. A vault at 24 still uses them as they are.
func TestTimeScaleLeavesTheRestAlone(t *testing.T) {
	fixed := map[string][2]time.Duration{
		"recovery wait unit (default)":  {defaultWaitUnit, 24 * time.Hour},
		"recovery quiet (default)":      {defaultQuiet, 72 * time.Hour},
		"connection request pending":    {ConnectionPending, 7 * 24 * time.Hour},
		"outgoing request":              {OutgoingRequestTTL, 8 * 24 * time.Hour},
		"handshake":                     {HandshakeTTL, 16 * 24 * time.Hour},
		"approved retention":            {ApprovedRetention, 16 * 24 * time.Hour},
		"dedupe retention":              {DedupeRetention, 16 * 24 * time.Hour},
		"response cache":                {ResponseRetention, 24 * time.Hour},
		"standing token max":            {StandingMax, 30 * 24 * time.Hour},
		"standing re-mint":              {StandingRemintBelow, 10 * 24 * time.Hour},
		"holder refresh":                {HolderRefreshBelow, 3 * 24 * time.Hour},
		"push registrations window":     {PushRegistrationsWin, 24 * time.Hour},
		"push renew":                    {PushRenewAfter, 30 * 24 * time.Hour},
		"name change interval":          {NameChangeInterval, 30 * 24 * time.Hour},
		"ask cooldown":                  {AskCooldownTTL, 7 * 24 * time.Hour},
		"ask rate window":               {AskRateWindow, 24 * time.Hour},
		"ask pause":                     {AskPauseWithin, 30 * 24 * time.Hour},
		"intro invite":                  {IntroInviteTTL, 24 * time.Hour},
		"signer refused notice":         {signerRefusedEvery, 24 * time.Hour},
		"hold off max":                  {MaxHoldOff, 30 * 24 * time.Hour},
		"held notice":                   {HeldNoticeEvery, 10 * time.Minute},
		"presence retry":                {presentRetry, time.Hour},
		"owner check minimum (setting)": {MinOwnerCheckInterval, time.Hour},
		"owner check default (setting)": {DefaultOwnerCheckInterval, 24 * time.Hour},
		"recovery delay (real)":         {RecoveryDelay, 24 * time.Hour},
		"recovery validity (real)":      {RecoveryValidity, 24 * time.Hour},
		"recovered invite (not scaled)": {RecoveredInviteWindow, 24 * time.Hour},
		"pending unlink (real)":         {PendingUnlinkTTL, 7 * 24 * time.Hour},
		"enroll window (real)":          {EnrollWindow, 24 * time.Hour},
		"counter notice (real)":         {CounterUnavailableNotice, 24 * time.Hour},
	}
	for name, v := range fixed {
		if v[0] != v[1] {
			t.Errorf("%s: %v, want %v", name, v[0], v[1])
		}
	}
	// The recovery wait unit and quiet period come from the channel file
	// and are used as they are: a vault at 24 does not divide them again.
	d := newDevFixture(t)
	d.m.opt.TimeScale = 24
	d.m.opt.RecoveryWaitUnit = 600 * time.Second
	if d.m.waitUnit() != 600*time.Second {
		t.Fatalf("wait unit %v at scale 24", d.m.waitUnit())
	}
	// At use sites: a request's cached answer is kept 24 h (retention),
	// and the recovered phone's invite renewed by a resumed unlock is
	// usable for 24 h (RecoveredInviteWindow), both at scale 24.
	t0 := time.Now()
	if err := d.send("vault.status", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if len(d.m.st.Responses) == 0 {
		t.Fatal("no cached answer")
	}
	for k, cr := range d.m.st.Responses {
		if left := cr.Expires.Sub(t0); left < 24*time.Hour-time.Minute || left > 24*time.Hour+time.Minute {
			t.Fatalf("cached answer %s kept %v at scale 24", k, left)
		}
	}
	d.m.mu.Lock()
	inv := &Invite{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0Z", Kind: KindApp, Used: true}
	now := time.Now()
	d.m.resumeLostOK(inv, now)
	d.m.mu.Unlock()
	if !inv.Exp.Equal(now.Add(24*time.Hour)) || inv.Used {
		t.Fatalf("recovered invite renewed to %v at scale 24", inv.Exp.Sub(now))
	}
	// Bounds of the owner-check setting are unchanged (real units).
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	body := func(n string) []byte {
		return []byte(`{"version":` + uitoa(d.m.st.Settings.Version) + `,"set":{"owner_check.interval_seconds":` + n + `}}`)
	}
	if next, err := ApplySettings(d.m.st.Settings, body("3599")); err == nil {
		t.Fatalf("a setting below an hour accepted at scale 24: %+v", next)
	}
	if next, err := ApplySettings(d.m.st.Settings, body("3600")); err != nil || next.OwnerCheckInterval() != time.Hour {
		t.Fatalf("an hour refused at scale 24: %v", err)
	}
}
