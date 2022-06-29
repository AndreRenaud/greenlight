package greenlight

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type github_details struct {
	client_id     string
	client_secret string
}

func (g *Greenlight) InstallGithubHandlers(r *mux.Router, id string, secret string) error {
	g.github = &github_details{
		client_id:     id,
		client_secret: secret,
	}

	r.HandleFunc("/api/auth/github/login", g.githubLoginHandler)
	r.HandleFunc("/api/auth/github/callback", g.githubCallbackHandler)

	return nil
}

func (g *Greenlight) githubLoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("login handler")
	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s%s", g.github.client_id, g.local_server, "/api/auth/github/callback")
	log.Printf("redirectURL %s", redirectURL)

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (g *Greenlight) githubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	githubAccessToken, err := g.getGithubAccessToken(code)
	if err != nil {
		panic(err)
	}

	githubData, err := getGithubData(githubAccessToken)
	if err != nil {
		panic(err)
	}
	log.Printf("Raw github data: %v", githubData)

	u := UserData{
		Name:     githubData["name"].(string),
		Email:    githubData["email"].(string),
		Provider: "github",
		Avatar:   githubData["avatar_url"].(string),
		URL:      githubData["html_url"].(string),
	}

	if err := g.SetUserData(u, w); err != nil {
		panic(err)
	}

	g.callback(w, r, &u)
}

func getGithubData(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	res := map[string]any{}
	if err := json.Unmarshal(respbody, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *Greenlight) getGithubAccessToken(code string) (string, error) {

	requestBodyMap := map[string]string{"client_id": g.github.client_id, "client_secret": g.github.client_secret, "code": code}
	requestJSON, err := json.Marshal(requestBodyMap)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(requestJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Represents the response received from Github
	type githubAccessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}

	var ghresp githubAccessTokenResponse
	json.Unmarshal(respbody, &ghresp)

	return ghresp.AccessToken, nil
}
