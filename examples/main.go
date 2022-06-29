package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/AndreRenaud/greenlight"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var github_client_id = flag.String("client_id", "", "GitHub Client ID")
var github_client_secret = flag.String("client_secret", "", "GitHub Client Secret")
var addr = flag.String("addr", ":8080", "http service address")
var embedded = flag.Bool("embedded", true, "If set, use embedded static files")
var google_json = flag.String("google_oauth_json", "", "Google OAuth Client Secret file for autenticating")

// Grab the static content & embed it into the binary
//go:embed static_files/*
var static_files embed.FS

var gl *greenlight.Greenlight

func loggedinHandler(w http.ResponseWriter, r *http.Request, u *greenlight.UserData) {
	log.Printf("Login User: %v", u)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	gl.ClearUserData(w)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")

	var raw []byte
	u, err := gl.GetUserData(r)
	var prettyJSON bytes.Buffer
	if err == nil {
		// Prettifying the json
		// json.indent is a library utility function to prettify JSON indentation
		raw, err = json.Marshal(u)
		if err != nil {
			log.Panicf("JSON marshal error: %s", err)
		}
	} else {
		raw, err = json.Marshal(map[string]string{"error": err.Error()})
		if err != nil {
			log.Panicf("JSON marshal error: %s", err)
		}
	}
	log.Printf("raw: %q", raw)
	if err := json.Indent(&prettyJSON, raw, "", "\t"); err != nil {
		log.Panic("JSON parse error")
	}

	// Return the prettified JSON as a string
	w.Write(prettyJSON.Bytes())
}

func main() {
	flag.Parse()

	log.Printf("Greenlight demo")

	r := mux.NewRouter()

	var err error
	if gl, err = greenlight.New(loggedinHandler); err != nil {
		log.Panicf("Unable to initialise Greenlight: %s", err)
	}

	if *github_client_id != "" {
		if err := gl.InstallGithubHandlers(r, *github_client_id, *github_client_secret); err != nil {
			log.Panic(err)
		}
	}
	if *google_json != "" {
		if err := gl.InstallGoogleHandlers(r, *google_json); err != nil {
			log.Panic(err)
		}
	}

	r.HandleFunc("/api/auth/user", userInfoHandler)
	r.HandleFunc("/api/auth/logout", logoutHandler)

	if *embedded {
		dir, _ := fs.Sub(static_files, "static_files")
		r.PathPrefix("/").Handler(http.FileServer(http.FS(dir)))
	} else {
		r.PathPrefix("/").Handler(http.FileServer(http.Dir("static_files")))

	}

	log.Printf("Running on http://%s", *addr)
	loggedRouter := handlers.LoggingHandler(os.Stdout, r)
	log.Fatal(http.ListenAndServe(*addr, loggedRouter))
}
