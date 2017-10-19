package ishare

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

// IShareClient is the interface for this client library.
type IShareClient interface {
	GenerateJWTToken() (string, error)
	AccessRequest() (*AccessToken, error)
}

// IShareClaims is a wrapper around JWT Standard claims, if the spec changes this is a convient way to implement custom claims.
type IShareClaims struct {
	*jwt.StandardClaims
}

// AccessToken holds the response access token
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// IShareClientConfig holds the configuration to start the authorization process.
type IShareClientConfig struct {
	EORI               string // Client EORI
	COC                string // Clients COC
	PublicKeyPath      string // path to public key file (myisharecertificate.cert.pem)
	PrivateKeyPath     string // Path to private key file (myishareprivate.key.pem)
	PrivateKeyPassword []byte // Private key password
	EORIRegistry       string // EORI Registry
	AccessRequestUrl   string // Holds the URL of the authorization registry
	StripCertificate   bool   // Strip the -----BEGIN CERTIFICATE----- and -----END CERTIIFCATE---- from your the certificate
}

// default iShare client
type iShareClient struct {
	config        *IShareClientConfig
	publicKey     *rsa.PublicKey
	publicKeyCert []byte
	privateKey    *rsa.PrivateKey
}

// NewClient returns a new iShare client, it loads and parses the iShare certificate files.
// It returns an error when the certificates can not be found or your private key password is incorrect.
func NewClient(config *IShareClientConfig) (IShareClient, error) {
	var ishare = &iShareClient{config: config}
	if err := ishare.parsePublicKey(); err != nil {
		return nil, err
	}

	if err := ishare.parsePrivateKey(); err != nil {
		return nil, err
	}

	return ishare, nil
}

// GenerateJWTToken returns a string holding a signed JWT token to build an access request.
// A error returns when the signing of the JWT-token failed.
func (i *iShareClient) GenerateJWTToken() (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	if i.config.StripCertificate {
		certificate := strings.Replace(string(i.publicKeyCert), "-----BEGIN CERTIFICATE-----", "", -1)
		certificate = strings.Replace(string(certificate), "-----END CERTIFICATE-----", "", -1)
		t.Header["x5c"] = string(certificate)
	} else {
		t.Header["x5c"] = string(i.publicKeyCert)
	}

	t.Claims = &IShareClaims{
		&jwt.StandardClaims{
			Id:        uuid.NewV4().String(),
			Issuer:    i.config.EORI,
			Subject:   i.config.EORI,
			Audience:  i.config.COC,
			IssuedAt:  time.Now().UTC().Unix(),
			ExpiresAt: time.Now().Add(30 * time.Second).UTC().Unix(),
		},
	}

	token, err := t.SignedString(i.privateKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

// Access Request executes the actual http(s) request.
// On success the access token will be returned.
// If something goes wrong ie http.Status Code != 200 it will return the error.
func (i *iShareClient) AccessRequest() (*AccessToken, error) {
	client := http.DefaultClient
	token, err := i.GenerateJWTToken()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", i.config.AccessRequestUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "iSHARE "+token)

	q := req.URL.Query()
	q.Add("grant_type", "client_credentials")
	q.Add("scope", "iSHARE")
	q.Add("client_id", i.config.EORI)
	q.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	q.Add("client_assertion", token)
	q.Add("authorisation_registry", i.config.EORIRegistry)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(string(body))
	}

	var accessToken = new(AccessToken)
	if err := json.NewDecoder(resp.Body).Decode(&accessToken); err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (i *iShareClient) parsePublicKey() error {
	var err error
	i.publicKeyCert, err = ioutil.ReadFile(i.config.PublicKeyPath)
	if err != nil {
		return err
	}

	i.publicKey, err = jwt.ParseRSAPublicKeyFromPEM(i.publicKeyCert)
	if err != nil {
		return err
	}

	return nil
}

func (i *iShareClient) parsePrivateKey() error {
	privateKey, err := ioutil.ReadFile(i.config.PrivateKeyPath)
	if err != nil {
		return err
	}

	p, err := i.decryptPrivateKey(privateKey, i.config.PrivateKeyPassword)
	if err != nil {
		return err
	}

	i.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(p)
	if err != nil {
		return err
	}

	return nil
}

func (i *iShareClient) decryptPrivateKey(key []byte, password []byte) ([]byte, error) {
	block, rest := pem.Decode(key)
	if len(rest) > 0 {
		return nil, errors.New("invalid certificate, extra data included")
	}

	if x509.IsEncryptedPEMBlock(block) {
		der, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der}), nil
	}

	return key, nil
}
