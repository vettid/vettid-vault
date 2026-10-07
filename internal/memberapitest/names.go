package memberapitest

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-vault/vault"
)

// The account's names (MEMBER-API 2.2.0, VAULT-MESSAGING 0.18.0 §10.8,
// §11.13): the snapshot carries first_name, last_name and name_change;
// members change the names only through their vault (account.name.set),
// whose request the host writes on the vault row (name_change,
// name_change_pending). ProcessNameChanges plays the vault-names job.

// memberNames is a member's names and when they last changed (zero: the
// registration names).
type memberNames struct {
	first, last string
	changedAt   time.Time
}

// nameResult is the vault row's name_change_result.
type nameResult struct {
	seq            uint64
	status, reason string
}

// names returns the member's current names: Config.Names, or Test Member,
// until a change was applied.
func (a *API) names(guid string) *memberNames {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nm == nil {
		a.nm, a.nr = map[string]*memberNames{}, map[string]*nameResult{}
	}
	n := a.nm[guid]
	if n == nil {
		n = &memberNames{first: "Test", last: "Member"}
		if a.cfg.Names != nil {
			n.first, n.last = a.cfg.Names(guid)
		}
		a.nm[guid] = n
	}
	c := *n
	return &c
}

// nameChange is the snapshot's name_change for the member.
func (a *API) nameChange(guid string) map[string]any {
	n := a.names(guid)
	nc := map[string]any{"allowed_after": nil, "last": nil}
	if !n.changedAt.IsZero() {
		if after := n.changedAt.Add(vault.NameChangeInterval); after.After(a.cfg.Now()) {
			nc["allowed_after"] = after.UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	a.mu.Lock()
	r := a.nr[guid]
	a.mu.Unlock()
	if r != nil {
		last := map[string]any{"seq": r.seq, "status": r.status}
		if r.reason != "" {
			last["reason"] = r.reason
		}
		nc["last"] = last
	}
	return nc
}

// ProcessNameChanges plays the member API's vault-names job for the
// member's current vault (MEMBER-API 2.2.0): it claims a pending request
// (a conditional REMOVE name_change_pending), refuses it (invalid,
// too_soon) or applies it, records name_change_result and pushes the
// snapshot. It returns the outcome ("" when nothing was pending).
func (a *API) ProcessNameChanges(ctx context.Context, guid string) (string, error) {
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil || active(cur) == nil {
		return "", err
	}
	it, err := VaultItem(ctx, a.cfg.DDB, a.cfg.Tables.Vaults, cur.VaultID)
	if err != nil {
		return "", err
	}
	p, _ := it["name_change_pending"].(*ddbtypes.AttributeValueMemberBOOL)
	m, _ := it["name_change"].(*ddbtypes.AttributeValueMemberM)
	if p == nil || !p.Value || m == nil {
		return "", nil
	}
	seqN, _ := num(m.Value, "seq")
	seq := uint64(seqN)
	if _, err := a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Vaults,
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(cur.VaultID)}, UpdateExpression: aws.String("REMOVE name_change_pending"),
		ConditionExpression:       aws.String("name_change_pending = :t AND name_change.seq = :seq"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":t": &ddbtypes.AttributeValueMemberBOOL{Value: true}, ":seq": n(seqN)}}); err != nil {
		if code(err) == "ConditionalCheckFailedException" {
			return "", nil // another run claimed it
		}
		return "", err
	}
	first, ok1 := vault.NormalizeRequestedName(str(m.Value, "first_name"))
	last, ok2 := vault.NormalizeRequestedName(str(m.Value, "last_name"))
	names := a.names(guid)
	res := &nameResult{seq: seq, status: vault.NameApplied}
	switch {
	case !ok1 || !ok2 || first == names.first && last == names.last:
		res.status, res.reason = vault.NameRefused, "invalid"
	case !names.changedAt.IsZero() && a.cfg.Now().Before(names.changedAt.Add(vault.NameChangeInterval)):
		res.status, res.reason = vault.NameRefused, "too_soon"
	}
	a.mu.Lock()
	if res.status == vault.NameApplied {
		a.nm[guid] = &memberNames{first: first, last: last, changedAt: a.cfg.Now()}
	}
	if old := a.nr[guid]; old == nil || old.seq <= seq {
		a.nr[guid] = res
	}
	a.mu.Unlock()
	result := map[string]ddbtypes.AttributeValue{"seq": n(seqN), "status": s(res.status)}
	if res.reason != "" {
		result["reason"] = s(res.reason)
	}
	if _, err := a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Vaults,
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(cur.VaultID)}, UpdateExpression: aws.String("SET name_change_result = :r"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":r": &ddbtypes.AttributeValueMemberM{Value: result}}}); err != nil {
		return "", err
	}
	if _, err := a.PushAccount(ctx, guid); err != nil {
		return "", err
	}
	return res.status, nil
}
