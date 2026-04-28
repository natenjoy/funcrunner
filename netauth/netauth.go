package netauth

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

var keyFile = "/opt/local/netdevops/etc/auth/auth.key"
var sharedCredsFile = "/opt/local/netdevops/etc/auth/globals.enc"
var userCredsFilename = ".creds.enc"

type Credential struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

var userCredentials Credential
var sharedGlobalCredentials map[string]Credential
var key []byte

func init() {
	// Load global crypto key
	key = GetSymmetricKeyFromFile(keyFile)
	// Load credentials globally for performance
	userCredentials = GetUserCredentials()
	sharedGlobalCredentials = GetSharedCredentials()
}

func SetUserCredentials() {
	var name string
	fmt.Printf("Please enter your username: ")
	fmt.Scanf("%s\n", &name)

	fmt.Printf("Please enter your password: ")
	password, err := terminal.ReadPassword(0)
	if err != nil {
		e := fmt.Sprintf("Error reading password: %s", err)
		log.Fatalf(e)
	}
	fmt.Printf("\n")

	cred := Credential{name, string(password)}
	bs, err := yaml.Marshal(cred)
	if err != nil {
		e := fmt.Sprintf("failure marshaling credentials: %s", err)
		log.Fatalf(e)
	}

	homeDirectory := os.Getenv("HOME")
	if homeDirectory == "" {
		e := fmt.Sprintf("failure to obtain home directory")
		log.Fatalf(e)
	}
	filename := homeDirectory + "/" + userCredsFilename

	err = EncryptToFile(key, bs, filename)
	if err != nil {
		e := fmt.Sprintf("failure encrypting to file: %s", err)
		log.Fatalf(e)
	}
	return
}

func GetUserCredentials() Credential {
	homeDirectory := os.Getenv("HOME")
	if homeDirectory == "" {
		e := fmt.Sprintf("failure to obtain home directory")
		log.Fatalf(e)
	}
	filename := homeDirectory + "/" + userCredsFilename
	bs, err := DecryptFromFile(key, filename)

       if err != nil {
                fmt.Printf("failure to decrypt user credential file: %s\n", err)
                fmt.Println("Please reset your password")
                SetUserCredentials()
                os.Exit(0)
        }

	var cred Credential
	err = yaml.Unmarshal(bs, &cred)
	if err != nil {
		e := fmt.Sprintf("failure to unmarshal credential: %s", err)
		log.Fatalf(e)
	}
	return cred
}

func GetSharedCredentials() map[string]Credential {
	bs, err := DecryptFromFile(key, sharedCredsFile)
	if err != nil {
		e := fmt.Sprintf("failure decrypting shared creds file %s: %s", sharedCredsFile, err)
		log.Fatalf(e)
	}

	var creds map[string]Credential
	err = yaml.Unmarshal(bs, &creds)
	if err != nil {
		e := fmt.Sprintf("failure unmarshaling yaml: %s", err)
		log.Fatalf(e)
	}

	return creds
}

func AddSharedCredentials(description, username, password string) {
	creds := GetSharedCredentials()
	creds[description] = Credential{username, password}
	bs, err := yaml.Marshal(creds)
	if err != nil {
		e := fmt.Sprintf("failure to marshal creds: %s", err)
		log.Fatalf(e)
	}

	err = EncryptToFile(key, bs, sharedCredsFile)
	if err != nil {
		e := fmt.Sprintf("failure encrypting to file: %s", err)
		log.Fatalf(e)
	}
	return
}

func DeleteSharedCredentials(description string) {
	creds := GetSharedCredentials()
	if _, ok := creds[description]; ok {
		delete(creds, description)
	}

	bs, err := yaml.Marshal(creds)
	if err != nil {
		e := fmt.Sprintf("failure to marshal creds: %s", err)
		log.Fatalf(e)
	}

	err = EncryptToFile(key, bs, sharedCredsFile)
	if err != nil {
		e := fmt.Sprintf("failure encrypting to file: %s", err)
		log.Fatalf(e)
	}
	return
}

// GetCredentials returns the appropriate credential based on the hostname and os
func GetCredentials(hostname, os string) Credential {
	deviceType := "UNKNOWN"
	if len(hostname) >= 10 {
		deviceType = string(hostname[7:10])
	}

	if cred, ok := sharedGlobalCredentials[os]; ok {
		return cred
	}
	if deviceType == "ofw" {
		return sharedGlobalCredentials["ofw"]
	}

	// Default use local user credential
	return userCredentials
}

func PrintAllCredentials() {
	for name, cred := range sharedGlobalCredentials {
		fmt.Printf("%s: %s \n", name, cred)
	}
	return
}
