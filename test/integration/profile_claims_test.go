//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDexLocalUserProfileClaimsLoginAndRefresh(t *testing.T) {
	dexHarness := startDexProfileClaimsHarness(t)
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	resource := newGeneratedLocalUser("claims-user", "claims@example.com", "claims-subject", "claims-user-secret")
	name := "Ada Lovelace"
	preferredUsername := "ada"
	verified := false
	resource.Spec.Name = &name
	resource.Spec.PreferredUsername = &preferredUsername
	resource.Spec.EmailVerified = &verified
	resource.Spec.Groups = &[]string{"developers", "operators"}
	mustCreate(t, ctx, harness.client, resource)
	awaitReadyLocalUser(t, ctx, harness.client, resource.Name)
	password := string(awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName).Data["password"])

	httpClient := dexLoginHTTPClient(t, dexHarness)
	code := completePasswordLogin(t, dexHarness, httpClient, resource.Spec.Email, password)
	tokens := exchangeAuthorizationCode(t, dexHarness, httpClient, code)
	assertProfileClaims(t, tokens.IDToken, name, preferredUsername, false, []string{"developers", "operators"})
	if tokens.RefreshToken == "" {
		t.Fatal("authorization code exchange omitted refresh_token")
	}
	refreshed := refreshTokens(t, dexHarness, httpClient, tokens.RefreshToken)
	assertProfileClaims(t, refreshed.IDToken, name, preferredUsername, false, []string{"developers", "operators"})
}

type oidcTokenResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func completePasswordLogin(t *testing.T, harness *dexHarness, client *http.Client, email, password string) string {
	t.Helper()
	issuer := dexIssuer(t, harness)
	redirectURI := "http://127.0.0.1/callback"
	response := mustHTTPGet(t, client, issuer+"/auth?"+url.Values{
		"client_id":     {"integration-client"},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile email groups offline_access"},
		"state":         {"profile-state"},
	}.Encode())
	body := readHTTPBody(t, response)
	response = mustSubmitForm(t, client, response.Request.URL, formAction(t, body), url.Values{"login": {email}, "password": {password}})
	defer response.Body.Close()
	location, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("state") != "profile-state" || location.Query().Get("code") == "" {
		t.Fatalf("OIDC callback = %s", location.Redacted())
	}
	return location.Query().Get("code")
}

func exchangeAuthorizationCode(t *testing.T, harness *dexHarness, client *http.Client, code string) oidcTokenResponse {
	t.Helper()
	return requestTokens(t, harness, client, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://127.0.0.1/callback"},
	})
}

func refreshTokens(t *testing.T, harness *dexHarness, client *http.Client, refreshToken string) oidcTokenResponse {
	t.Helper()
	return requestTokens(t, harness, client, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func requestTokens(t *testing.T, harness *dexHarness, client *http.Client, values url.Values) oidcTokenResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, dexIssuer(t, harness)+"/token", strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("integration-client", "integration-secret")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		t.Fatalf("token endpoint returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var tokens oidcTokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.IDToken == "" {
		t.Fatal("token endpoint omitted id_token")
	}
	return tokens
}

func dexIssuer(t *testing.T, harness *dexHarness) string {
	t.Helper()
	mapped, err := url.Parse(harness.httpURL)
	if err != nil {
		t.Fatal(err)
	}
	return mapped.Scheme + "://dex.test:5556/dex"
}

func assertProfileClaims(t *testing.T, rawIDToken, name, preferredUsername string, emailVerified bool, groups []string) {
	t.Helper()
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		t.Fatal("id_token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		EmailVerified     bool     `json:"email_verified"`
		Groups            []string `json:"groups"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Name != name || claims.PreferredUsername != preferredUsername || claims.EmailVerified != emailVerified || !equalStrings(claims.Groups, groups) {
		t.Fatalf("profile claims = name %q preferred_username %q email_verified %t groups %#v", claims.Name, claims.PreferredUsername, claims.EmailVerified, claims.Groups)
	}
}
