//go:build integration

package parent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/vettid-vault/internal/memberapitest"
)

// The AWS backend against LocalStack (VAULT_IT_LOCALSTACK): S3
// conditional writes, SQS, and the DynamoDB lease, lifecycle and slot
// conditions.
func TestAWSBackend(t *testing.T) {
	ep := os.Getenv("VAULT_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("VAULT_IT_LOCALSTACK not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)
	pfx := "ut" + hex.EncodeToString(rb)
	creds := credentials.NewStaticCredentialsProvider("test", "test", "")
	ac := aws.Config{Region: "us-east-1", Credentials: creds}
	s3c := s3.NewFromConfig(ac, func(o *s3.Options) { o.BaseEndpoint = aws.String(ep); o.UsePathStyle = true })
	if _, err := s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(pfx + "-bucket")}); err != nil {
		t.Fatal(err)
	}
	db := dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ep) })
	tn := memberapitest.Tables{Vaults: pfx + "-vaults", Instances: pfx + "-instances", Requests: pfx + "-requests", Releases: pfx + "-releases"}
	if err := memberapitest.CreateTables(ctx, db, tn); err != nil {
		t.Fatal(err)
	}
	a, err := NewAWS(AWSConfig{Region: "us-east-1", Credentials: creds, Endpoint: ep, Bucket: pfx + "-bucket",
		VaultsTable: tn.Vaults, InstancesTable: tn.Instances, RequestsTable: tn.Requests, EmulateConditionalDelete: true})
	if err != nil {
		t.Fatal(err)
	}

	// S3: create-only, version-matched, conditional delete.
	k := "vaults/v1/state"
	v1, err := a.Put(ctx, k, []byte("one"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Put(ctx, k, []byte("again"), ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create-only over an existing object: %v", err)
	}
	v2, err := a.Put(ctx, k, []byte("two"), v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Put(ctx, k, []byte("stale"), v1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	b, v, err := a.Get(ctx, k)
	if err != nil || string(b) != "two" || v != v2 {
		t.Fatalf("get: %q %v", b, err)
	}
	if err := a.Delete(ctx, k, v1); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete with a stale version: %v", err)
	}
	if err := a.Delete(ctx, k, v2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Get(ctx, k); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}

	// SQS.
	url, err := a.Create(ctx, pfx+"-vault-control-i1")
	if err != nil {
		t.Fatal(err)
	}
	qs, err := a.List(ctx, pfx+"-vault-control-")
	if err != nil || len(qs) != 1 {
		t.Fatalf("list: %v %v", qs, err)
	}
	if err := a.Destroy(ctx, url); err != nil {
		t.Fatal(err)
	}

	// DynamoDB: leases need the vault row.
	if err := a.AcquireLease(ctx, "v1", "i1", 100, 280); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("lease on a missing row: %v", err)
	}
	if _, err := db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &tn.Vaults, Item: map[string]ddbAttr{"vault_id": s("v1"), "user_guid": s("u"), "state": s("enrolling")}}); err != nil {
		t.Fatal(err)
	}
	if err := a.AcquireLease(ctx, "v1", "i1", 100, 280); err != nil {
		t.Fatal(err)
	}
	if err := a.AcquireLease(ctx, "v1", "i2", 200, 380); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("live lease taken: %v", err)
	}
	if err := a.RenewLease(ctx, "v1", "i2", 400); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("foreign renew: %v", err)
	}
	if err := a.AcquireLease(ctx, "v1", "i2", 300, 480); err != nil {
		t.Fatalf("expired lease not taken: %v", err)
	}
	// i1's events no longer apply.
	pcr := "aa" + hex.EncodeToString(make([]byte, 47))
	if err := a.Lifecycle(ctx, Lifecycle{Event: "unlocked", VaultID: "v1", Release: pcr, VaultVersion: pcr, StateVersion: 1}, "i1", time.Now()); err != nil {
		t.Fatal(err)
	}
	it, _ := memberapitest.VaultItem(ctx, db, tn.Vaults, "v1")
	if st := it["state"].(*ddbS).Value; st != "enrolling" {
		t.Fatalf("loser wrote state %q", st)
	}
	if err := a.Lifecycle(ctx, Lifecycle{Event: "unlocked", VaultID: "v1", Release: pcr, VaultVersion: pcr, StateVersion: 1}, "i2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.Lifecycle(ctx, Lifecycle{Event: "moved", VaultID: "v1", Release: pcr, VaultVersion: pcr, StateVersion: 1}, "i2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.Lifecycle(ctx, Lifecycle{Event: "locked", VaultID: "v1", Release: pcr, VaultVersion: pcr, StateVersion: 1}, "i2", time.Now()); err != nil {
		t.Fatal(err)
	}
	it, _ = memberapitest.VaultItem(ctx, db, tn.Vaults, "v1")
	if it["state"].(*ddbS).Value != "locked" || it["sealed_release"].(*ddbS).Value != pcr || it["lease"] != nil {
		t.Fatalf("lifecycle: %v", it)
	}

	// Slots: only queued slots are answered.
	if _, err := db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &tn.Requests, Item: map[string]ddbAttr{"request_id": s("r1"), "status": s("queued")}}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSlot(ctx, "r1", Slot{Status: "done", Envelope: make([]byte, 5252)}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSlot(ctx, "r1", Slot{Status: "expired"}); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteSlot(ctx, "missing", Slot{Status: "done", Code: "etk_unknown"}); err != nil {
		t.Fatal(err)
	}
	r, _ := db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &tn.Requests, Key: map[string]ddbAttr{"request_id": s("r1")}})
	if r.Item["status"].(*ddbS).Value != "done" || len(r.Item["envelope"].(*ddbS).Value) != 7004 {
		t.Fatalf("slot: %v", r.Item)
	}
	r, _ = db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &tn.Requests, Key: map[string]ddbAttr{"request_id": s("missing")}})
	if r.Item != nil {
		t.Fatal("slot created by the parent")
	}
}

type (
	ddbAttr = ddbtypes.AttributeValue
	ddbS    = ddbtypes.AttributeValueMemberS
)
