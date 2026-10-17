// SPDX-License-Identifier: BUSL-1.1
package repository

import "testing"

// QA finding: these common shapes were not recognised, so whole files with
// credentials could be sent to a model.
func TestLikelySecretShapes(t *testing.T) {
	for _, line := range []string{
		`{"password": "Sup3rS3cret!"}`, `"token" : "eyJhbGciOiJIUzI1NiJ9"`, `STRIPE = "sk_live_51Habcdefghijkl"`,
		`token = "github_pat_11ABCDEFG0123456789_abcdefghij"`, `DATABASE_URL=postgres://admin:hunter22@db.internal/app`,
		`aws_secret_access_key = wJalrXUtnFEMI/K7MDENG`, `const k = "AIzaSyD-1234567890abcdefghijklmnopqrstu"`,
		`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc`, `password='letmein123'`,
		`DB_PASS=hunter22x`, `	password := "s3cretValue"`, `'password' => 'hunter22x',`, `define('DB_PASSWORD', 'hunter22x');`, `<password>hunter22x</password>`,
		`<add key="ApiKey" value="abcdef123456"/>`, `signing_key = "k3y-material-xyz"`, `HMAC_KEY=abcdef123456`, `Authorization: Basic dXNlcjpwYXNzd29yZA==`,
		`url = "https://hooks.slack.com/services/T000/B000/XXXX"`, `DefaultEndpointsProtocol=https;AccountName=a;AccountKey=abcdefghijklmnopqrstuvwx==`, `//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`,
	} {
		if !likelySecret.MatchString(line) {
			t.Error("missed:", line)
		}
	}
	for _, line := range []string{`def check_password(user, candidate):`, `return render("login.html")`, `see https://example.com/docs`} {
		if likelySecret.MatchString(line) {
			t.Error("false positive:", line)
		}
	}
}
