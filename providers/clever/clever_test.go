package clever_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/clever"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := cleverProvider()
	a.Equal(provider.ClientKey, os.Getenv("CLEVER_KEY"))
	a.Equal(provider.Secret, os.Getenv("CLEVER_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := cleverProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*clever.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "clever.com/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("CLEVER_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=profile+email+openid")
}

func Test_BeginAuthWithPrompt(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := cleverProvider()
	provider.SetPrompt("test", "prompts")
	session, err := provider.BeginAuth("test_state")
	s := session.(*clever.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "clever.com/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("CLEVER_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=profile+email+openid")
	a.Contains(s.AuthURL, "prompt=test+prompts")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), cleverProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := cleverProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://accounts.google.com/o/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*clever.Session)
	a.Equal(session.AuthURL, "https://accounts.google.com/o/oauth2/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func cleverProvider() *clever.Provider {
	return clever.New(os.Getenv("CLEVER_KEY"), os.Getenv("CLEVER_SECRET"), "/foo")
}
