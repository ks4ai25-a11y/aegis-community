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
