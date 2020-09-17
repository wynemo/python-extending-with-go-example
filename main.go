package main


import "C"

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"log"
	"math/big"
	"os"
)

var (
	defaultUid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

const DEBUG = false

var logger = log.New(os.Stdout, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)

func Debug(info string) {
	if DEBUG {
		logger.Println(info)
	}
}

func Verify(pubKey *sm2.PublicKey, body, signature string) bool {
	Debug(fmt.Sprintln("pubkey: ", pubKey))

	d64, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		Debug(fmt.Sprintln("base64 decode error: ", err))
	}

	l := len(d64)
	br := d64[:l/2]
	bs := d64[l/2:]

	var ri, si big.Int
	r := ri.SetBytes(br)
	s := si.SetBytes(bs)
	v := sm2.Sm2Verify(pubKey, []byte(body), defaultUid, r, s)
	return v
}

func B2S(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(ba)
}

func Cert2PubKey(cert []byte) *sm2.PublicKey {
	block, _ := pem.Decode(cert)
	pub, e := sm2.ParseCertificate(block.Bytes)
	if e != nil {
		fmt.Println(e)
		os.Exit(-1)
	}
	var sm2Pub sm2.PublicKey
	pubECDSA := pub.PublicKey.(*ecdsa.PublicKey)
	sm2Pub.Curve = pubECDSA.Curve
	sm2Pub.X = pubECDSA.X
	sm2Pub.Y = pubECDSA.Y

	return &sm2Pub
}

func test() {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIICMjCCAdagAwIBAgIQAQAAAAAAAAAAAAAAAAAACTAMBggqgRzPVQGDdQUAMDkx
CzAJBgNVBAYTAkNOMQwwCgYDVQQKDANHREQxDzANBgNVBAsMBjAwMDAwMDELMAkG
A1UEAwwCMzMwHhcNMjAwNDIyMDI0MTUwWhcNNDAwNDIyMDI0MTUwWjBKMQswCQYD
VQQGEwJDTjEMMAoGA1UECgwDR0REMQwwCgYDVQQLDANHREQxDTALBgNVBAMMBFRl
c3QxEDAOBgNVBAcMB0JlaUppbmcwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR6
g36fyH3/jfUZn8p3pPv+iZ0r/zcQvR6WCRzJLhcJakbxhkABtibBYo1cOCf6FhFQ
oC4zb+lXZLcAIwXE+zFHo4GsMIGpMB0GA1UdDgQWBBQ5cHBnoXxottYuxQRvhJy5
XoH6IzBwBgNVHSMEaTBngBSAk7Li6h+IprAEm9bpd4UwP+weFKE9pDswOTELMAkG
A1UEBhMCQ04xDDAKBgNVBAoMA0dERDEPMA0GA1UECwwGMDAwMDAwMQswCQYDVQQD
DAIzM4IQBAAAAAAAAAAAAAAAAAAABDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIGwDAM
BggqgRzPVQGDdQUAA0gAMEUCIQCoFxYf7BWY7PoJvDr7O9BKzxvbARknjtIm9hNl
qMgZVgIgY6lmLraj2br2RvTTfKxFaP2/rQTZUA+9rEPllMopFyo=
-----END CERTIFICATE-----`)
	pub := Cert2PubKey(cert)
	println(pub)
	body := "202009081234+张三+2020-09-08 14:51:39+2020-09-29 00:00:00+1.3.2.1"
	//signature, _ := Sign(body)
	str := "/5Vyd/K38gpPSHodvrvInO8iuf9j9ptTx8wQRg47FsGx/Pv6Rg13wAsqjBRRtDdeFUuA63ZlOjrtMN32a8ngRQ=="
	log.Println("signature-----------", str)

	Verify(pub, body, str)
}

//export sum
func sum(certStr, originStr, signature string) int {
	log.Println("sum-----------", certStr)
	log.Println("sum-----------", originStr)
	log.Println("sum-----------", signature)
	cert, _ := base64.StdEncoding.DecodeString(certStr)
	origin, _ := base64.StdEncoding.DecodeString(originStr)
	pubKey := Cert2PubKey(cert)
	ret := Verify(pubKey, string(origin), signature)
	if !ret {
		return -1
	}
	return 0
}

func main() {}

