package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/miguelmota/go-solidity-sha3"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
	"os"
	"strings"
)

var log string

// step 1 gen private key
func PrivateKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	key := hex.EncodeToString(bytes)
	log = "Private Key = \n"+key+ "\n"
	return key, nil
}

// step 2 get public key
func Publickey(privateKey string) (publicKey string) {
	var e ecdsa.PrivateKey
	e.D, _ = new(big.Int).SetString(privateKey, 16)
	e.PublicKey.Curve = secp256k1.S256()
	e.PublicKey.X, e.PublicKey.Y = e.PublicKey.Curve.ScalarBaseMult(e.D.Bytes())
	return strings.ToUpper(fmt.Sprintf("%x", elliptic.Marshal(secp256k1.S256(), e.X, e.Y)))
}

// step 3 hash keccak256
func keccak265(publickey string) string {
	pub := publickey[2:]
	hash := solsha3.SoliditySHA3(
		solsha3.Address(pub),
	)
	hashed := strings.ToUpper(hex.EncodeToString(hash))
	return hashed
}

// step 4 5
func sha256hasher(hexval string) string {
	data, _ := hex.DecodeString(hexval)
	hash := sha256.Sum256(data)
	h1 := hex.EncodeToString(hash[:])
	return h1
}
//final
func randomAddressGen() string {
	priv, _ := PrivateKey(32)
	pub := Publickey(priv)
	keccak := keccak265(pub)
	keccak_last_40 := keccak[24:]
	keccak_last_40_41 := "41" + keccak_last_40
	hash1 := sha256hasher(keccak_last_40_41)
	hash2 := sha256hasher(hash1)
	checksum := hash2[:8]
	addressHex := keccak_last_40_41 + checksum
	data, _ := hex.DecodeString(addressHex)
	walletAddr := base58.Encode(data)
  log = log+"for wallet = \n"+ walletAddr
	return walletAddr
}
func checker(walletaddr string) bool {
	targets := []string{"TE9orCSw8hASgBfVkFTAtYCdMTABz5uX4G",
		"TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi",
		"TJ9dzc6T3PSfbHWPJEYEzmg7GwzEwiWiiF"}
	// dummy := "TJ9dzc6T3PSfbHWPJEYEzmg7GwzEwiWiiF"
	var isfound bool
	for _, a := range targets {
		isfound = a == walletaddr
	}
	return isfound
}

func main() {

	for {
		walletfound := checker(randomAddressGen())
    
		if walletfound {
      f, _ := os.Create("logs.txt")
      f.WriteString(log)
			break
		}
	}
 fmt.Println("Running ...")
}
