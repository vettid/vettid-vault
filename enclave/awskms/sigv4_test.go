package awskms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var exampleCreds = Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

// Vectors from the AWS Signature Version 4 test suite (get-vanilla,
// post-vanilla, get-vanilla-query-order-key-case).
func TestSigV4Suite(t *testing.T) {
	ts := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	empty := sha256Hex(nil)
	for _, c := range []struct {
		method, url, sig string
	}{
		{"GET", "https://example.amazonaws.com/", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
		{"POST", "https://example.amazonaws.com/", "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"},
		{"GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"},
	} {
		req, _ := http.NewRequest(c.method, c.url, nil)
		Sign(req, empty, exampleCreds, "us-east-1", "service", ts)
		want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=" + c.sig
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("%s %s:\n got %s\nwant %s", c.method, c.url, got, want)
		}
	}
}

func randString(n int, alphabet string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b.WriteByte(alphabet[k.Int64()])
	}
	return b.String()
}

// The signer agrees with the AWS SDK's (test-only dependency; the SDK is
// never linked into the enclave) on random KMS-shaped requests, with and
// without a session token.
func TestSigV4MatchesSDK(t *testing.T) {
	sdk := v4.NewSigner()
	for i := 0; i < 200; i++ {
		body := []byte(randString(i, "abcdefghijklmnopqrstuvwxyz{}\":,"))
		cr := Credentials{AccessKeyID: "ASIA" + randString(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), SecretAccessKey: randString(40, "abcdefABCDEF0123456789/+")}
		if i%2 == 0 {
			cr.SessionToken = randString(300, "abcdefABCDEF0123456789/+=")
		}
		region := []string{"us-east-1", "eu-west-1", "ap-southeast-2"}[i%3]
		ts := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
		url := "https://kms." + region + ".amazonaws.com/"
		if i%5 == 0 {
			url += "a%20b/c?x=1&y=a%2Fb&x=0"
		}
		mk := func() *http.Request {
			r, _ := http.NewRequest("POST", url, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/x-amz-json-1.1")
			r.Header.Set("X-Amz-Target", fmt.Sprintf("TrentService.Op%d", i))
			return r
		}
		mine := mk()
		Sign(mine, sha256Hex(body), cr, region, "kms", ts)
		theirs := mk()
		if cr.SessionToken != "" {
			theirs.Header.Set("X-Amz-Security-Token", cr.SessionToken)
		}
		err := sdk.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey, SessionToken: cr.SessionToken},
			theirs, sha256Hex(body), "kms", region, ts)
		if err != nil {
			t.Fatal(err)
		}
		if a, b := mine.Header.Get("Authorization"), theirs.Header.Get("Authorization"); a != b {
			t.Fatalf("request %d:\n mine   %s\n sdk    %s", i, a, b)
		}
	}
}

func TestURIEncode(t *testing.T) {
	if got := uriEncode("a b/ü~", true); got != "a%20b/%C3%BC~" {
		t.Fatal(got)
	}
	if got := hex.EncodeToString([]byte(uriEncode("/", false))); got != hex.EncodeToString([]byte("%2F")) {
		t.Fatal(got)
	}
}
