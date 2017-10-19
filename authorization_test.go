package ishare

import (
	"flag"
	"log"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func init() {
	flag.Parse()
	viper.SetConfigName("ishare.config")
	viper.AddConfigPath(".")
	viper.SetConfigType("toml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("fatal error config file:\n%s", err.Error())
	}

}

func TestRefImpLogin(t *testing.T) {
	clientConfig := &IShareClientConfig{
		EORI:               viper.GetString("client.EORI"),
		COC:                viper.GetString("client.COC"),
		PublicKeyPath:      viper.GetString("client.PublicKeyPath"),
		PrivateKeyPath:     viper.GetString("client.PrivateKeyPath"),
		PrivateKeyPassword: []byte(viper.GetString("client.PrivateKeyPassword")),
		EORIRegistry:       "EU.EORI.NL000000001",
		StripCertificate:   true,
		AccessRequestUrl:   "http://refimp.ishare-project.org/scheme_owner/oauth2.0/token",
	}

	ishare, err := NewClient(clientConfig)
	assert.Nil(t, err)

	token, err := ishare.AccessRequest()
	assert.Nil(t, err)

	log.Printf("Refimp client logon")
	log.Printf("Access token: %s", token.AccessToken)
	log.Printf("Token type: %s", token.TokenType)
	log.Printf("Expires in %d\n\n", token.ExpiresIn)
}

func TestPortBaseLogin(t *testing.T) {
	clientConfig := &IShareClientConfig{
		EORI:               viper.GetString("client.EORI"),
		COC:                viper.GetString("client.COC"),
		PublicKeyPath:      viper.GetString("client.PublicKeyPath"),
		PrivateKeyPath:     viper.GetString("client.PrivateKeyPath"),
		PrivateKeyPassword: []byte(viper.GetString("client.PrivateKeyPassword")),
		EORIRegistry:       "EU.EORI.NL000000001",
		StripCertificate:   false,
		AccessRequestUrl:   "https://lmm68qs94c.execute-api.eu-west-1.amazonaws.com/POC/portbase/authorisation_registry/oauth2.0/token",
	}

	ishare, err := NewClient(clientConfig)
	assert.Nil(t, err)

	token, err := ishare.AccessRequest()
	assert.Nil(t, err)

	log.Printf("Portbase client logon")
	log.Printf("Access token: %s", token.AccessToken)
	log.Printf("Token type: %s", token.TokenType)
	log.Printf("Expires in %d\n\n", token.ExpiresIn)
}
