package selfmadedepot

import (
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/micromdm/scep/v2/cryptoutil"
	"github.com/micromdm/scep/v2/scep"
)

// Signer signs x509 certificates and stores them in a Depot
type Signer struct {
	depot            Depot
	caPass           string
	allowRenewalDays int
	validityDays     int
}

// Option customizes Signer
type Option func(*Signer)

// NewSigner creates a new Signer　・・ここ変えていったらり
func NewSigner(depot Depot, opts ...Option) *Signer {
	s := &Signer{
		depot:            depot,
		allowRenewalDays: 14,
		validityDays:     365,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithCAPass specifies the password to use with an encrypted CA key
func WithCAPass(pass string) Option {
	return func(s *Signer) {
		s.caPass = pass
	}
}

// WithAllowRenewalDays sets the allowable renewal time for existing certs
func WithAllowRenewalDays(r int) Option {
	return func(s *Signer) {
		s.allowRenewalDays = r
	}
}

// WithValidityDays sets the validity period new certs will use
func WithValidityDays(v int) Option {
	return func(s *Signer) {
		s.validityDays = v
	}
}

// SignCSR signs a certificate using Signer's Depot CA
func (s *Signer) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	id, err := cryptoutil.GenerateSubjectKeyID(m.CSR.PublicKey)
	if err != nil {
		return nil, err
	}
	//serial
	serial, err := s.depot.Serial()
	if err != nil {
		return nil, err
	}

	// create cert template
	//Japane Time これが必要
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      m.CSR.Subject,
		NotBefore:    time.Now().Add(-600).UTC(),
		NotAfter:     time.Now().AddDate(0, 0, s.validityDays).UTC(),
		SubjectKeyId: id,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		SignatureAlgorithm: m.CSR.SignatureAlgorithm,
		DNSNames:           m.CSR.DNSNames,
		EmailAddresses:     m.CSR.EmailAddresses,
		IPAddresses:        m.CSR.IPAddresses,
		URIs:               m.CSR.URIs,
	}

	caCerts, caKey, err := s.depot.CA([]byte(s.caPass))
	if err != nil {
		return nil, err
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}

	name := certName(crt)

	// Connect to the server in order to determin if it is ok to destribute the cert
	// revocation is done if the validity of the existing certificate is
	// less than allowRenewalDays
	_, err = s.depot.Destribute(name, s.allowRenewalDays, crt)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}
