//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	cdpnetwork "github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	formActionPattern = regexp.MustCompile(`<form[^>]+action="([^"]+)"`)
	qrCodePattern     = regexp.MustCompile(`src="data:image/png;base64,([^"]+)"`)
)

func TestMFATOTP(t *testing.T) {
	dexHarness := startDexMFAHarness(t, "totp-1")
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	oauth := newConfidentialOAuth2Client("mfa-totp-client")
	oauth.Spec.RedirectURIs = []string{"http://client.test:5556/callback"}
	oauth.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "mfa-totp-client-secret"}}
	user := newGeneratedLocalUser("mfa-totp-user", "mfa-totp@example.com", "mfa-totp-subject", "mfa-totp-password")
	for _, resource := range []client.Object{oauth, user} {
		mustCreate(t, ctx, harness.client, resource)
	}
	awaitReadyOAuth2Client(t, ctx, harness.client, oauth.Name)
	managed := awaitReadyLocalUser(t, ctx, harness.client, user.Name)
	password := string(awaitSecret(t, ctx, harness.client, user.Spec.Password.Generated.SecretName).Data["password"])
	clientSecret := string(awaitSecret(t, ctx, harness.client, oauth.Spec.Secret.Generated.SecretName).Data["clientSecret"])

	totpURI := completeTOTPLogin(t, dexHarness, oauth.Spec.ID, oauth.Spec.RedirectURIs[0], user.Spec.Email, password)
	managed = awaitMFAInventory(t, ctx, harness, user.Name, func(devices []dexv1alpha1.MFADeviceStatus) bool {
		return len(devices) == 1 && devices[0].AuthenticatorID == "totp-1" && devices[0].Type == "TOTP" && devices[0].Confirmed
	})
	assertMFASecretSafe(t, ctx, harness, managed.Status, append([]string{totpURI, password, clientSecret}, harnessTLSMaterial(t, dexHarness)...)...)

	previousGeneration := managed.Generation
	managed.Spec.MFA = &dexv1alpha1.DexLocalUserMFASpec{RemoveAuthenticatorIDs: []string{"totp-1"}}
	mustUpdate(t, ctx, harness.client, managed)
	managed = awaitReadyLocalUserAfter(t, ctx, harness.client, user.Name, previousGeneration)
	awaitMFAInventory(t, ctx, harness, user.Name, func(devices []dexv1alpha1.MFADeviceStatus) bool { return len(devices) == 0 })
	assertRemoteMFAEmpty(t, ctx, harness, managed.Status.ResolvedUserID)
	assertMFAReplayConverged(t, ctx, harness, user.Name, "")

	previousGeneration = managed.Generation
	managed.Spec.MFA.RemoveAuthenticatorIDs = nil
	mustUpdate(t, ctx, harness.client, managed)
	awaitReadyLocalUserAfter(t, ctx, harness.client, user.Name, previousGeneration)
	completeTOTPLogin(t, dexHarness, oauth.Spec.ID, oauth.Spec.RedirectURIs[0], user.Spec.Email, password)
	managed = awaitMFAInventory(t, ctx, harness, user.Name, func(devices []dexv1alpha1.MFADeviceStatus) bool { return len(devices) == 1 })

	previousGeneration = managed.Generation
	managed.Spec.MFA.ResetNonce = "reset-1"
	mustUpdate(t, ctx, harness.client, managed)
	managed = awaitReadyLocalUserAfter(t, ctx, harness.client, user.Name, previousGeneration)
	if managed.Status.HandledMFAResetNonce != "reset-1" || len(managed.Status.MFADevices) != 0 {
		t.Fatalf("MFA reset status = %#v", managed.Status)
	}
	assertRemoteMFAEmpty(t, ctx, harness, managed.Status.ResolvedUserID)

	assertMFAReplayConverged(t, ctx, harness, user.Name, "reset-1")
}

func TestMFAWebAuthn(t *testing.T) {
	dexHarness := startDexMFAHarness(t, "webauthn-1")
	harness := startKubernetesHarness(t, dexHarness)
	browser := newWebAuthnBrowser(t, startWebAuthnBrowser(t, dexHarness))
	ctx := context.Background()

	oauth := newConfidentialOAuth2Client("mfa-webauthn-client")
	oauth.Spec.RedirectURIs = []string{"http://client.test:5556/callback"}
	oauth.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "mfa-webauthn-client-secret"}}
	user := newGeneratedLocalUser("mfa-webauthn-user", "mfa-webauthn@example.com", "mfa-webauthn-subject", "mfa-webauthn-password")
	for _, resource := range []client.Object{oauth, user} {
		mustCreate(t, ctx, harness.client, resource)
	}
	awaitReadyOAuth2Client(t, ctx, harness.client, oauth.Name)
	managed := awaitReadyLocalUser(t, ctx, harness.client, user.Name)
	password := string(awaitSecret(t, ctx, harness.client, user.Spec.Password.Generated.SecretName).Data["password"])
	clientSecret := string(awaitSecret(t, ctx, harness.client, oauth.Spec.Secret.Generated.SecretName).Data["clientSecret"])

	browser.completeLogin(t, oauth.Spec.ID, oauth.Spec.RedirectURIs[0], user.Spec.Email, password)
	managed = awaitMFAInventory(t, ctx, harness, user.Name, func(devices []dexv1alpha1.MFADeviceStatus) bool {
		return len(devices) == 1 && devices[0].AuthenticatorID == "webauthn-1" && len(devices[0].WebAuthnCredentials) == 1
	})
	credentialID := managed.Status.MFADevices[0].WebAuthnCredentials[0].CredentialID
	credential := browser.credential(t, credentialID)
	assertMFASecretSafe(t, ctx, harness, managed.Status, append(
		[]string{password, clientSecret, credential.PrivateKey, webAuthnPublicKey(t, credential.PrivateKey)},
		harnessTLSMaterial(t, dexHarness)...,
	)...)

	previousGeneration := managed.Generation
	managed.Spec.MFA = &dexv1alpha1.DexLocalUserMFASpec{RemoveWebAuthnCredentialIDs: []string{credentialID}}
	mustUpdate(t, ctx, harness.client, managed)
	managed = awaitReadyLocalUserAfter(t, ctx, harness.client, user.Name, previousGeneration)
	awaitMFAInventory(t, ctx, harness, user.Name, func(devices []dexv1alpha1.MFADeviceStatus) bool { return len(devices) == 0 })
	assertRemoteMFAEmpty(t, ctx, harness, managed.Status.ResolvedUserID)
	assertMFAReplayConverged(t, ctx, harness, user.Name, "")

	previousGeneration = managed.Generation
	managed.Spec.MFA.RemoveWebAuthnCredentialIDs = nil
	mustUpdate(t, ctx, harness.client, managed)
	awaitReadyLocalUserAfter(t, ctx, harness.client, user.Name, previousGeneration)
	browser.completeLogin(t, oauth.Spec.ID, oauth.Spec.RedirectURIs[0], user.Spec.Email, password)
	managed = awaitMFAInventory(t, ctx, harness, user.Name, func(devices []dexv1alpha1.MFADeviceStatus) bool {
		return len(devices) == 1 && len(devices[0].WebAuthnCredentials) == 1
	})

	previousGeneration = managed.Generation
	managed.Spec.MFA.ResetNonce = "reset-1"
	mustUpdate(t, ctx, harness.client, managed)
	managed = awaitReadyLocalUserAfter(t, ctx, harness.client, user.Name, previousGeneration)
	if managed.Status.HandledMFAResetNonce != "reset-1" || len(managed.Status.MFADevices) != 0 {
		t.Fatalf("WebAuthn reset status = %#v", managed.Status)
	}
	assertRemoteMFAEmpty(t, ctx, harness, managed.Status.ResolvedUserID)
	assertMFAReplayConverged(t, ctx, harness, user.Name, "reset-1")
}

type webAuthnBrowser struct {
	ctx             context.Context
	authenticatorID webauthn.AuthenticatorID
}

func newWebAuthnBrowser(t *testing.T, browserURL string) *webAuthnBrowser {
	t.Helper()
	allocatorContext, cancelAllocator := chromedp.NewRemoteAllocator(context.Background(), browserURL)
	browserContext, cancelBrowser := chromedp.NewContext(allocatorContext)
	t.Cleanup(cancelBrowser)
	t.Cleanup(cancelAllocator)
	result := &webAuthnBrowser{ctx: browserContext}
	if err := chromedp.Run(browserContext,
		webauthn.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			id, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
				Protocol:                    webauthn.AuthenticatorProtocolCtap2,
				Ctap2version:                webauthn.Ctap2versionCtap20,
				Transport:                   webauthn.AuthenticatorTransportUsb,
				HasResidentKey:              true,
				HasUserVerification:         true,
				AutomaticPresenceSimulation: true,
				IsUserVerified:              true,
			}).Do(ctx)
			result.authenticatorID = id
			return err
		}),
	); err != nil {
		t.Fatal(err)
	}
	return result
}

func (browser *webAuthnBrowser) completeLogin(t *testing.T, clientID, redirectURI, email, password string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(browser.ctx, 20*time.Second)
	defer cancel()
	authorizeURL := "https://dex.test:5556/dex/auth?" + url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {"mfa-state"},
	}.Encode()
	var location string
	runErr := chromedp.Run(ctx,
		cdpnetwork.ClearBrowserCookies(),
		chromedp.Navigate(authorizeURL),
		chromedp.WaitVisible("#login", chromedp.ByQuery),
		chromedp.SendKeys("#login", email, chromedp.ByQuery),
		chromedp.SendKeys("#password", password, chromedp.ByQuery),
		chromedp.Click("#submit-login", chromedp.ByQuery),
		chromedp.WaitVisible("#webauthn-btn", chromedp.ByQuery),
		chromedp.Evaluate(`startWebAuthn()`, nil),
	)
	if runErr != nil {
		var pageError string
		diagnosticContext, diagnosticCancel := context.WithTimeout(browser.ctx, 2*time.Second)
		defer diagnosticCancel()
		_ = chromedp.Run(diagnosticContext,
			chromedp.Location(&location),
			chromedp.Evaluate(`document.getElementById("webauthn-error")?.textContent || ""`, &pageError),
		)
		if !validOIDCCallback(location) {
			page, _ := url.Parse(location)
			t.Fatalf("complete WebAuthn login at %s://%s%s: %v: %s", page.Scheme, page.Host, page.Path, runErr, pageError)
		}
	}
	if runErr == nil {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if err := chromedp.Run(ctx, chromedp.Location(&location)); err == nil {
				callback, parseErr := url.Parse(location)
				if parseErr == nil && callback.Hostname() == "client.test" {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("code") == "" || callback.Query().Get("state") != "mfa-state" {
		var pageError string
		diagnosticContext, diagnosticCancel := context.WithTimeout(browser.ctx, 2*time.Second)
		defer diagnosticCancel()
		_ = chromedp.Run(diagnosticContext, chromedp.Evaluate(`document.getElementById("webauthn-error")?.textContent || ""`, &pageError))
		t.Fatalf("WebAuthn OIDC flow stopped at %s://%s%s: %s", callback.Scheme, callback.Host, callback.Path, pageError)
	}
}

func validOIDCCallback(location string) bool {
	callback, err := url.Parse(location)
	return err == nil && callback.Hostname() == "client.test" && callback.Query().Get("code") != "" && callback.Query().Get("state") == "mfa-state"
}

func (browser *webAuthnBrowser) credential(t *testing.T, credentialID string) *webauthn.Credential {
	t.Helper()
	var credentials []*webauthn.Credential
	if err := chromedp.Run(browser.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		credentials, err = webauthn.GetCredentials(browser.authenticatorID).Do(ctx)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	for _, credential := range credentials {
		if credential.CredentialID == credentialID || normalizedCredentialID(credential.CredentialID) == credentialID {
			return credential
		}
	}
	t.Fatalf("virtual authenticator lacks credential %q", credentialID)
	return nil
}

func normalizedCredentialID(value string) string {
	if decoded, err := decodeBase64(value); err == nil {
		return base64.RawURLEncoding.EncodeToString(decoded)
	}
	return ""
}

func webAuthnPublicKey(t *testing.T, encodedPrivateKey string) string {
	t.Helper()
	der, err := decodeBase64(encodedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("WebAuthn private key type = %T", parsed)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

func decodeBase64(value string) ([]byte, error) {
	var lastErr error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func completeTOTPLogin(t *testing.T, harness *dexHarness, clientID, redirectURI, email, password string) string {
	t.Helper()
	httpClient := dexLoginHTTPClient(t, harness)
	authorizeURL := "https://dex.test:5556/dex/auth?" + url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {"mfa-state"},
	}.Encode()
	response := mustHTTPGet(t, httpClient, authorizeURL)
	body := readHTTPBody(t, response)
	response = mustSubmitForm(t, httpClient, response.Request.URL, formAction(t, body), url.Values{"login": {email}, "password": {password}})
	body = readHTTPBody(t, response)
	totpURI := decodeTOTPQRCode(t, qrCode(t, body))
	code := currentTOTPCode(t, totpURI, time.Now())
	response = mustSubmitForm(t, httpClient, response.Request.URL, formAction(t, body), url.Values{"totp": {code}})
	defer response.Body.Close()
	location, err := response.Location()
	if err != nil {
		t.Fatalf("OIDC callback redirect: %v", err)
	}
	if location.Scheme+"://"+location.Host+location.Path != redirectURI || location.Query().Get("code") == "" || location.Query().Get("state") != "mfa-state" {
		t.Fatalf("OIDC callback = %s", location.Redacted())
	}
	return totpURI
}

func dexLoginHTTPClient(t *testing.T, harness *dexHarness) *http.Client {
	t.Helper()
	mapped, err := url.Parse(harness.httpURL)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	caPEM, err := os.ReadFile(harness.clientTLS.CA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("load Dex test CA")
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "dex.test", MinVersion: tls.VersionTLS12}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "dex.test:5556" {
			address = mapped.Host
		}
		return dialer.DialContext(ctx, network, address)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   10 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.Hostname() == "client.test" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func mustHTTPGet(t *testing.T, client *http.Client, requestURL string) *http.Response {
	t.Helper()
	response, err := client.Get(requestURL)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		t.Fatalf("GET %s returned %s", response.Request.URL.Redacted(), response.Status)
	}
	return response
}

func mustSubmitForm(t *testing.T, client *http.Client, base *url.URL, action string, values url.Values) *http.Response {
	t.Helper()
	actionURL, err := base.Parse(html.UnescapeString(action))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.PostForm(actionURL.String(), values)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusSeeOther {
		defer response.Body.Close()
		t.Fatalf("POST %s returned %s", actionURL.Redacted(), response.Status)
	}
	return response
}

func readHTTPBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func formAction(t *testing.T, body []byte) string {
	t.Helper()
	match := formActionPattern.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("Dex form action not found in %d-byte response", len(body))
	}
	return string(match[1])
}

func qrCode(t *testing.T, body []byte) string {
	t.Helper()
	match := qrCodePattern.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("Dex TOTP QR code not found in %d-byte response", len(body))
	}
	return string(match[1])
}

func decodeTOTPQRCode(t *testing.T, encoded string) string {
	t.Helper()
	pngBytes, err := base64.StdEncoding.DecodeString(html.UnescapeString(encoded))
	if err != nil {
		t.Fatal(err)
	}
	image, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatal(err)
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(image)
	if err != nil {
		t.Fatal(err)
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		t.Fatal(err)
	}
	if uri := result.GetText(); strings.HasPrefix(uri, "otpauth://totp/") {
		return uri
	}
	t.Fatal("Dex QR code did not contain a TOTP enrollment URI")
	return ""
}

func currentTOTPCode(t *testing.T, uri string, now time.Time) string {
	t.Helper()
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(parsed.Query().Get("secret")))
	if err != nil || len(secret) == 0 {
		t.Fatal("invalid TOTP secret in enrollment URI")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	digest := hmac.New(sha1.New, secret)
	_, _ = digest.Write(counter[:])
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func awaitMFAInventory(t *testing.T, ctx context.Context, harness *kubernetesHarness, name string, check func([]dexv1alpha1.MFADeviceStatus) bool) *dexv1alpha1.DexLocalUser {
	t.Helper()
	var result *dexv1alpha1.DexLocalUser
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexLocalUser{}
		if err := harness.client.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		if check(resource.Status.MFADevices) && readyConditionSet(resource.Status.Conditions, resource.Generation) {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func assertRemoteMFAEmpty(t *testing.T, ctx context.Context, harness *kubernetesHarness, userID string) {
	t.Helper()
	devices, found, err := harness.dexClient.ListMFADevices(ctx, userID, "local")
	if err != nil || !found || len(devices) != 0 {
		t.Fatalf("remote MFA inventory: found=%t devices=%d err=%v", found, len(devices), err)
	}
}

func assertMFAReplayConverged(t *testing.T, ctx context.Context, harness *kubernetesHarness, name, resetNonce string) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
	managed := getLocalUser(t, ctx, harness.client, name)
	if !readyConditionSet(managed.Status.Conditions, managed.Generation) || len(managed.Status.MFADevices) != 0 || managed.Status.HandledMFAResetNonce != resetNonce {
		t.Fatalf("MFA replay did not remain converged: %#v", managed.Status)
	}
}

func assertMFASecretSafe(t *testing.T, ctx context.Context, harness *kubernetesHarness, status dexv1alpha1.DexLocalUserStatus, secrets ...string) {
	t.Helper()
	statusJSON, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	events := &corev1.EventList{}
	if err := harness.client.List(ctx, events, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	eventsJSON, err := json.Marshal(events.Items)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		for name, observed := range map[string]string{"status": string(statusJSON), "logs": harness.logs.String(), "events": string(eventsJSON)} {
			if strings.Contains(observed, secret) {
				t.Fatalf("%s exposed MFA secret material", name)
			}
		}
	}
}

func harnessTLSMaterial(t *testing.T, harness *dexHarness) []string {
	t.Helper()
	result := make([]string, 0, 2)
	for _, path := range []string{harness.clientTLS.Cert, harness.clientTLS.Key} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, string(contents))
	}
	return result
}
