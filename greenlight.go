package greenlight

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/gorilla/securecookie"
)

type UserData struct {
	Provider string
	Name     string
	Email    string
	Avatar   string
	URL      string
}

type Greenlight struct {
	cookieHandler *securecookie.SecureCookie

	callback func(http.ResponseWriter, *http.Request, *UserData)

	github *github_details

	local_server string
}

func New(callback func(http.ResponseWriter, *http.Request, *UserData)) (*Greenlight, error) {
	if callback == nil {
		return nil, fmt.Errorf("no user login callback supplied")
	}
	/* Create a random ID */
	id := make([]byte, 32)
	if n, err := rand.Read(id); n != 32 || err != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("insufficient random bytes read")
	}

	// todo: load & save keys to avoid regeneration each restart
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)

	return &Greenlight{
		cookieHandler: securecookie.New(hashKey, blockKey),
		callback:      callback,
		local_server:  "http://localhost:8080", // TODO: Work this out from the request? or be told be the user?
	}, nil
}

func (g *Greenlight) GetUserData(r *http.Request) (*UserData, error) {
	// Otherwise, check if we're attaching via session cookie
	if cookie, err := r.Cookie("session"); err == nil {
		var u UserData
		if err = g.cookieHandler.Decode("session", cookie.Value, &u); err == nil {
			return &u, nil
		}
	}

	return nil, fmt.Errorf("no user data available")
}

func (g *Greenlight) SetUserData(user UserData, response http.ResponseWriter) error {
	encoded, err := g.cookieHandler.Encode("session", &user)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:  "session",
		Value: encoded,
		Path:  "/",
	}
	http.SetCookie(response, cookie)
	return nil
}

func (g *Greenlight) ClearUserData(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}
