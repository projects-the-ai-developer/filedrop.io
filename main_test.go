// main_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// TestSessionAuth_Redirects_Unauthenticated tests that an unauthenticated user is redirected.
func TestSessionAuth_Redirects_Unauthenticated(t *testing.T) {
	// Initialize a dummy session store
	store = sessions.NewCookieStore([]byte("a-very-secret-key"))

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	// A dummy handler that should not be reached
	dummyHandler := func(w http.ResponseWriter, r *http.Request) {
		t.Error("dummyHandler was called by an unauthenticated user")
	}

	// Create the handler with the sessionAuth middleware
	handler := http.HandlerFunc(sessionAuth(dummyHandler))
	handler.ServeHTTP(rr, req)

	// Check for redirect status
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusFound)
	}

	// Check the redirect location
	redirectURL, err := rr.Result().Location()
	if err != nil {
		t.Fatalf("could not get redirect location: %v", err)
	}
	if redirectURL.Path != "/login" {
		t.Errorf("handler redirected to wrong location: got %v want %v",
			redirectURL.Path, "/login")
	}
}

// TestSessionAuth_Allows_Authenticated tests that an authenticated user is allowed.
func TestSessionAuth_Allows_Authenticated(t *testing.T) {
	// Initialize a dummy session store
	store = sessions.NewCookieStore([]byte("a-very-secret-key"))

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new session
	session, _ := store.Get(req, "filedrop-session")
	session.Values["authenticated"] = true
	session.Values["last_activity"] = time.Now().Unix()

	// Save the session to a temporary recorder to get the cookie
	rrWithCookie := httptest.NewRecorder()
	if err := session.Save(req, rrWithCookie); err != nil {
		t.Fatalf("could not save session: %v", err)
	}
	// Set the cookie on the actual request
	req.Header.Set("Cookie", rrWithCookie.Header().Get("Set-Cookie"))

	// The actual recorder for the handler call
	rr := httptest.NewRecorder()

	// A dummy handler that we expect to be called
	dummyHandlerCalled := false
	dummyHandler := func(w http.ResponseWriter, r *http.Request) {
		dummyHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	}

	// Create the handler with the sessionAuth middleware
	handler := http.HandlerFunc(sessionAuth(dummyHandler))
	handler.ServeHTTP(rr, req)

	// Check for OK status
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check that the dummy handler was actually called
	if !dummyHandlerCalled {
		t.Error("dummyHandler was not called for an authenticated user")
	}
}