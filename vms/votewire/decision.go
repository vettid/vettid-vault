package votewire

// How a vote is decided and the outcome its results state (BALLOT-PROTOCOL
// 0.14.0 §3.5, §7.1, §8.5), as the reference implementation
// (vettid/service-vault vote/outcome.go) computes them.

// Decision rules.
const (
	RuleMajority  = "majority"
	RuleThreshold = "threshold"
	RulePlurality = "plurality"
)

// Bases: what a majority or a threshold is of.
const (
	BaseCast  = "cast"  // the ballots for a real choice (abstain left out)
	BaseVoted = "voted" // every ballot, abstain included
	BaseElig  = "elig"  // the proposal's eligible members
)

// MaxThresholdDen is the largest denominator of a threshold.
const MaxThresholdDen = 10

// Outcome statuses.
const (
	StatusDecided    = "decided"
	StatusNotDecided = "not_decided"
	StatusTied       = "tied"
	StatusNoQuorum   = "no_quorum"
)

// Threshold is a fraction num/den of the base.
type Threshold struct {
	Num int64 `json:"num"`
	Den int64 `json:"den"`
}

// Decision is a proposal's rule, its base (null for plurality) and its
// threshold (only for the threshold rule, else null).
type Decision struct {
	Rule      string     `json:"rule"`
	Base      *string    `json:"base"`
	Threshold *Threshold `json:"threshold"`
}

// Outcome is the results' outcome: whether the quorum was met, the status,
// and the decided choice (only when decided, else null).
type Outcome struct {
	QuorumMet bool    `json:"quorum_met"`
	Status    string  `json:"status"`
	Choice    *string `json:"choice"`
}

func gcd(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Validate checks a decision against §3.5: plurality with no base and no
// threshold; majority or threshold with a base of cast, voted or elig; a
// threshold exactly for the threshold rule, 1 ≤ den ≤ 10, 1 ≤ num ≤ den,
// above one half (2·num > den) and in lowest terms.
func (d *Decision) Validate() error {
	switch d.Rule {
	case RulePlurality:
		if d.Base != nil {
			return ErrDocument
		}
	case RuleMajority, RuleThreshold:
		if d.Base == nil {
			return ErrDocument
		}
		switch *d.Base {
		case BaseCast, BaseVoted, BaseElig:
		default:
			return ErrDocument
		}
	default:
		return ErrDocument
	}
	if (d.Rule == RuleThreshold) != (d.Threshold != nil) {
		return ErrDocument
	}
	if t := d.Threshold; t != nil {
		if t.Den < 1 || t.Den > MaxThresholdDen || t.Num < 1 || t.Num > t.Den || 2*t.Num <= t.Den || gcd(t.Num, t.Den) != 1 {
			return ErrDocument
		}
	}
	return nil
}

// Validate checks an outcome's own consistency (§8.5): a known status,
// quorum_met false exactly for no_quorum, and a choice exactly when decided,
// a real choice's id.
func (o *Outcome) Validate() error {
	switch o.Status {
	case StatusDecided, StatusNotDecided, StatusTied, StatusNoQuorum:
	default:
		return ErrDocument
	}
	if o.QuorumMet == (o.Status == StatusNoQuorum) || (o.Choice != nil) != (o.Status == StatusDecided) ||
		o.Choice != nil && (!ValidChoiceID(*o.Choice) || *o.Choice == AbstainID) {
		return ErrDocument
	}
	return nil
}

// Equal reports whether two outcomes are the same.
func (o Outcome) Equal(x Outcome) bool {
	if o.QuorumMet != x.QuorumMet || o.Status != x.Status || (o.Choice == nil) != (x.Choice == nil) {
		return false
	}
	return o.Choice == nil || *o.Choice == *x.Choice
}

// Decide computes the outcome (§7.1) from the proposal, the tally and the
// number of ballots. It refuses a decision §3.5 doesn't allow, a tally that
// doesn't name exactly the proposal's choices, a negative count, a sum other
// than ballots, or more ballots than eligible members. Integers only: every
// count is at most ballots, itself at most eligible (at most 100,000 in a
// valid proposal), and den at most 10, so nothing overflows.
func Decide(p *Proposal, tally map[string]int64, ballots int64) (Outcome, error) {
	if err := p.Decision.Validate(); err != nil {
		return Outcome{}, err
	}
	if len(tally) != len(p.Choices) || ballots < 0 || ballots > p.Eligible {
		return Outcome{}, ErrDocument
	}
	var sum, cast int64
	for _, c := range p.Choices {
		n, ok := tally[c.ID]
		if !ok || n < 0 || n > ballots { // no count above the ballots: the sums below stay in range
			return Outcome{}, ErrDocument
		}
		sum += n
		if c.ID != AbstainID {
			cast += n
		}
	}
	if sum != ballots {
		return Outcome{}, ErrDocument
	}
	// 1. The quorum, first: no_quorum whatever the tally.
	if ballots < p.Quorum.MinBallots {
		return Outcome{Status: StatusNoQuorum}, nil
	}
	decided := func(id string) Outcome { return Outcome{QuorumMet: true, Status: StatusDecided, Choice: &id} }
	none := Outcome{QuorumMet: true, Status: StatusNotDecided}
	d := p.Decision
	// 2. Plurality: the one real choice with the top count above 0; a top
	// count held by several is tied; every real choice at 0 decides nothing.
	if d.Rule == RulePlurality {
		var top int64
		var at []string
		for _, c := range p.Choices {
			if c.ID == AbstainID {
				continue
			}
			switch n := tally[c.ID]; {
			case n > top:
				top, at = n, []string{c.ID}
			case n == top:
				at = append(at, c.ID)
			}
		}
		switch {
		case top == 0:
			return none, nil
		case len(at) == 1:
			return decided(at[0]), nil
		default:
			return Outcome{QuorumMet: true, Status: StatusTied}, nil
		}
	}
	// 3. Majority and threshold: the base, and a base of 0 decides nothing.
	var base int64
	switch *d.Base {
	case BaseCast:
		base = cast
	case BaseVoted:
		base = ballots
	case BaseElig:
		base = p.Eligible
	}
	if base == 0 {
		return none, nil
	}
	// Over the real choices only; at most one can qualify, a threshold being
	// above one half.
	var won []string
	for _, c := range p.Choices {
		if c.ID == AbstainID {
			continue
		}
		n := tally[c.ID]
		if d.Rule == RuleMajority && 2*n > base || d.Rule == RuleThreshold && n*d.Threshold.Den >= base*d.Threshold.Num {
			won = append(won, c.ID)
		}
	}
	switch len(won) {
	case 0:
		return none, nil
	case 1:
		return decided(won[0]), nil
	default:
		return Outcome{}, ErrDocument
	}
}
