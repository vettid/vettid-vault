package callwire

// LowerWins reports whether call x wins a glare against call y
// (VAULT-MESSAGING §10.10 "Glare", C2, CALLS-PLAN V6, D21): two members
// calling each other at once, each vault holding its own call x ringing
// when the other's offer y arrives. The call_ids are compared as their 26
// ASCII bytes and the lower one wins, so both vaults agree. Equal ids never
// reach it: an offer with a known call_id is a duplicate.
func LowerWins(x, y string) bool { return x < y }
