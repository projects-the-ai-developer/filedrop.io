// main_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIndexHandler_Unauthorized(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	
	handler := http.HandlerFunc(basicAuth(indexHandler))
  handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}
