package twitter

import (
	"fmt"
	"testing"
	"time"

	"github.com/corpix/uarand"
	"github.com/dgryski/dgoogauth"
)

func Test_Login(t *testing.T) {
	twitter := NewTwitter()
	username := "AlfredKell4406"
	password := "dd8nra2ti2"
	secret := "IOVY2KDNWGE6MF6I"
	cookie, err := twitter.Login(username, password, secret)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(cookie)
}

func Test_GetGuestToken(t *testing.T) {
	twitter := NewTwitter()
	guestToken, err := twitter.GetGuestToken()
	if err != nil {
		t.Error(err)
	}
	fmt.Println(guestToken)
}

func Test_GenerateOTP(t *testing.T) {
	secret := "W44AO2PIY5O6CAYB"

	code := dgoogauth.ComputeCode(secret, time.Now().Unix()/30)

	fmt.Println(fmt.Sprintf("%06d", code))
}

func Test_GenerateUserAgent(t *testing.T) {
	for i := 0; i < 10; i++ {
		userAgent := uarand.GetRandom()
		fmt.Println(userAgent)
	}
}