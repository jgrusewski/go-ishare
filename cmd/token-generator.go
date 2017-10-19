package main

import (
	"flag"
	"log"

	ishare "github.com/jgrusewski/go-ishare"
	"github.com/spf13/viper"
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

func main() {
	minimalConfig := &ishare.ClientConfig{
		EORI:               viper.GetString("client.EORI"),
		COC:                viper.GetString("client.COC"),
		PublicKeyPath:      viper.GetString("client.PublicKeyPath"),
		PrivateKeyPath:     viper.GetString("client.PrivateKeyPath"),
		PrivateKeyPassword: []byte(viper.GetString("client.PrivateKeyPassword")),
	}

	client, err := ishare.NewClient(minimalConfig)
	if err != nil {
		log.Fatal(err)
	}

	token, err := client.GenerateJWTToken()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("JWTToken:\n%s", token)
}
