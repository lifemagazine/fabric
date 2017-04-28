/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

//WARNING - this chaincode's ID is hard-coded in chaincode_example04 to illustrate one way of
//calling chaincode from a chaincode. If this example is modified, chaincode_example04.go has
//to be modified as well with the new ID of chaincode_example02.
//chaincode_example05 show's how chaincode ID can be passed in as a parameter instead of
//hard-coding.

import (
	"fmt"
	//"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("issuecertificate Init")
	_, args := stub.GetFunctionAndParameters()
	var id string
	var privateBytes []byte
	var certificateBytes []byte

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	privateBytes, certificateBytes = create_pri_cert()

	// Initialize the chaincode
	id = args[0]
	fmt.Printf("init ID: %s\n", id)
	fmt.Printf("\n-----Private Key-----\n%s\n", privateBytes)
	fmt.Printf("\n-----Certificate-----\n%s\n", certificateBytes)

	// Write the state to the ledger
	err := stub.PutState(id, certificateBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(privateBytes)
}

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("issuecertificate Invoke")
	function, args := stub.GetFunctionAndParameters()
	if function == "invoke" {
		// Make payment of X units from A to B
		return t.invoke(stub, args)
	} else if function == "delete" {
		// Deletes an entity from its state
		return t.delete(stub, args)
	} else if function == "query" {
		// the old "Query" is now implemtned in invoke
		return t.query(stub, args)
	}

	return shim.Error("Invalid invoke function name. Expecting \"invoke\" \"delete\" \"query\"")
}

// Transaction makes creating new certificate and private key for id
func (t *SimpleChaincode) invoke(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var id string    // Entities
	var err error

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 3")
	}

	privateBytes, certificateBytes := create_pri_cert()

	// Initialize the chaincode
	id = args[0]
	fmt.Printf("invoke ID: %s\n", id)
	fmt.Printf("\n-----Private Key-----\n%s\n", privateBytes)
	fmt.Printf("\n-----Certificate-----\n%s\n", certificateBytes)

	// Write the state to the ledger
	err = stub.PutState(id, certificateBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(privateBytes)
}

// Deletes an entity from state
func (t *SimpleChaincode) delete(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	id := args[0]

	// Delete the key from the state in ledger
	err := stub.DelState(id)
	if err != nil {
		return shim.Error("Failed to delete state")
	}

	return shim.Success(nil)
}

// query callback representing the query of a chaincode
func (t *SimpleChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var id string // Entities
	var err error

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting name of the person to query")
	}

	id = args[0]

	// Get the state from the ledger
	certificateBytes, err := stub.GetState(id)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + id + "\"}"
		return shim.Error(jsonResp)
	}

	if certificateBytes == nil {
		jsonResp := "{\"Error\":\"Nil amount for " + id + "\"}"
		return shim.Error(jsonResp)
	}

	jsonResp := "{\"ID\":\"" + id + "\",\"certificate\":\"" + string(certificateBytes) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return shim.Success(certificateBytes)
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}


var (
	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func create_pri_cert() (privateBytes []byte, certificateBytes []byte){
	flag.Parse()

	/*if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}*/
	*host = "skinfosec.com"

	var priv interface{}
	var err error
	switch *ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", *ecdsaCurve)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certificateBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	fmt.Printf("----- CERTIFICATE -----\n%s\n", certificateBytes)

	privateBytes = pem.EncodeToMemory(pemBlockForKey(priv))
	fmt.Printf("----- PRIVATE KEY -----\n%s\n", privateBytes)

	/*certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("written cert.pem\n")

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()
	log.Print("written key.pem\n")*/

	return
}
