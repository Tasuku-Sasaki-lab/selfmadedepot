package selfmadedepot

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

// Depot is a repository for managing certificates
type Depot interface {
	CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error)
	Serial() (*big.Int, error)
	Destribute(name string,allowTime int, cert *x509.Certificate) (bool, error)
}
