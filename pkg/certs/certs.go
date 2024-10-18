package certs

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"strings"
)

func GenerateSelfSignedCert(domain string, organization string, validityInMonths int) (string, string, error) {

	var certsSB strings.Builder
	var privkeySB strings.Builder

	certTemplate := GenerateCertTemplate(domain, organization, validityInMonths)
	privateKey, err := GenerateKey()
	if err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	// Create the self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	// Encode and write the certificate in PEM format
	if err := pem.Encode(&certsSB, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	// Marshal private key and write it in PEM format
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}
	if err := pem.Encode(&privkeySB, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return certsSB.String(), privkeySB.String(), nil
	}

	log.Printf("Self-signed certificate generated: %s.crt and %s.key", domain, domain)
	return certsSB.String(), privkeySB.String(), nil
}
