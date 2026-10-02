package memberapitest

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateTables creates the four vault tables with the keys and indexes of
// vettid.org lib/stacks/data-stack.ts.
func CreateTables(ctx context.Context, db *dynamodb.Client, t Tables) error {
	S, N := ddbtypes.ScalarAttributeTypeS, ddbtypes.ScalarAttributeTypeN
	attr := func(name string, typ ddbtypes.ScalarAttributeType) ddbtypes.AttributeDefinition {
		return ddbtypes.AttributeDefinition{AttributeName: aws.String(name), AttributeType: typ}
	}
	key := func(pk string, sk ...string) []ddbtypes.KeySchemaElement {
		k := []ddbtypes.KeySchemaElement{{AttributeName: aws.String(pk), KeyType: ddbtypes.KeyTypeHash}}
		if len(sk) > 0 {
			k = append(k, ddbtypes.KeySchemaElement{AttributeName: aws.String(sk[0]), KeyType: ddbtypes.KeyTypeRange})
		}
		return k
	}
	gsi := func(name, pk, sk string, proj ddbtypes.Projection) ddbtypes.GlobalSecondaryIndex {
		return ddbtypes.GlobalSecondaryIndex{IndexName: aws.String(name), KeySchema: key(pk, sk), Projection: &proj}
	}
	all := ddbtypes.Projection{ProjectionType: ddbtypes.ProjectionTypeAll}
	specs := []dynamodb.CreateTableInput{
		{TableName: aws.String(t.Vaults), KeySchema: key("vault_id"),
			AttributeDefinitions:   []ddbtypes.AttributeDefinition{attr("vault_id", S), attr("user_guid", S), attr("created_at", S)},
			GlobalSecondaryIndexes: []ddbtypes.GlobalSecondaryIndex{gsi("user-index", "user_guid", "created_at", all)}},
		{TableName: aws.String(t.Instances), KeySchema: key("instance_id"),
			AttributeDefinitions: []ddbtypes.AttributeDefinition{attr("instance_id", S), attr("release", S), attr("heartbeat_at", N)},
			GlobalSecondaryIndexes: []ddbtypes.GlobalSecondaryIndex{gsi(releaseIndex, "release", "heartbeat_at",
				ddbtypes.Projection{ProjectionType: ddbtypes.ProjectionTypeInclude, NonKeyAttributes: []string{"load"}})}},
		{TableName: aws.String(t.Requests), KeySchema: key("request_id"),
			AttributeDefinitions: []ddbtypes.AttributeDefinition{attr("request_id", S)}},
		{TableName: aws.String(t.Releases), KeySchema: key("release"),
			AttributeDefinitions:   []ddbtypes.AttributeDefinition{attr("release", S), attr("status", S), attr("release_number", N)},
			GlobalSecondaryIndexes: []ddbtypes.GlobalSecondaryIndex{gsi(statusIndex, "status", "release_number", all)}},
	}
	for i := range specs {
		specs[i].BillingMode = ddbtypes.BillingModePayPerRequest
		if _, err := db.CreateTable(ctx, &specs[i]); err != nil {
			return err
		}
	}
	for _, name := range []string{t.Instances, t.Requests} {
		if _, err := db.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{TableName: aws.String(name),
			TimeToLiveSpecification: &ddbtypes.TimeToLiveSpecification{AttributeName: aws.String("expires_at"), Enabled: aws.Bool(true)}}); err != nil {
			return err
		}
	}
	return nil
}

// PutRelease writes a vault-releases row (operations render these from
// the signed manifest).
func PutRelease(ctx context.Context, db *dynamodb.Client, table, pcr0 string, number uint64, status string) error {
	_, err := db.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(table), Item: map[string]ddbtypes.AttributeValue{
		"release": s(pcr0), "release_number": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(number, 10)}, "status": s(status)}})
	return err
}

// VaultItem returns a vault row's raw attributes (assertions).
func VaultItem(ctx context.Context, db *dynamodb.Client, table, vaultID string) (map[string]ddbtypes.AttributeValue, error) {
	r, err := db.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(vaultID)}})
	if err != nil {
		return nil, err
	}
	return r.Item, nil
}

// ExpireLease sets a vault's lease expiry in the past (tests that force
// two instances to hold one vault).
func ExpireLease(ctx context.Context, db *dynamodb.Client, table, vaultID string) error {
	_, err := db.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(table),
		Key:                       map[string]ddbtypes.AttributeValue{"vault_id": s(vaultID)},
		UpdateExpression:          aws.String("SET #l.#e = :past"),
		ExpressionAttributeNames:  map[string]string{"#l": "lease", "#e": "lease_expires_at"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":past": n(1)}})
	return err
}
