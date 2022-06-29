package greenlight

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
var googleOauthConfig = &oauth2.Config{
	//ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	//ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
	Scopes:   []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint: google.Endpoint,
}

type googleOauthJson struct {
	Web struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"web"`
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func (g *Greenlight) InstallGoogleHandlers(r *mux.Router, auth_file string) error {
	content, err := ioutil.ReadFile(auth_file)
	if err != nil {
		return err
	}
	var oauth_json googleOauthJson
	if err := json.Unmarshal(content, &oauth_json); err != nil {
		return err
	}
	googleOauthConfig.ClientID = oauth_json.Web.ClientID
	googleOauthConfig.ClientSecret = oauth_json.Web.ClientSecret

	googleOauthConfig.RedirectURL = fmt.Sprintf("%s/api/auth/google/callback", g.local_server)

	r.HandleFunc("/api/auth/google/login", g.oauthGoogleLogin)
	r.HandleFunc("/api/auth/google/callback", g.oauthGoogleCallback)

	return nil
}

func (g *Greenlight) oauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)

	//AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must always provide a non-empty string and
	//validate that it matches the the state query parameter on your redirect callback.
	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func (g *Greenlight) oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
	log.Printf("Raw Google Login data: %v -> %v", data, m)

	u := UserData{
		Email:    m["email"].(string),
		Avatar:   m["picture"].(string),
		Provider: "google",
	}
	if err := g.SetUserData(u, w); err != nil {
		panic(err)
	}

	g.callback(w, r, &u)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}
