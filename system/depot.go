package system

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"time"
)

// New SystemDepot returns a new cert depot.
func NewSystemDepot(path string) (*systemDepot, error) {
	return &systemDepot{dirPath: path}, nil
}

type systemDepot struct {
	dirPath string
}

func (d *fileDepot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	caPEM, err := d.getFile("ca.pem")
	if err != nil {
		return nil, nil, err
	}
	cert, err := loadCert(caPEM.Data)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := d.getFile("ca.key")
	if err != nil {
		return nil, nil, err
	}
	key, err := loadKey(keyPEM.Data, pass)
	if err != nil {
		return nil, nil, err
	}
	return []*x509.Certificate{cert}, key, nil
}

type file struct {
	Info os.FileInfo
	Data []byte
}

func (d *systemDepot) check(path string) error {
	name := d.path(path)
	_, err := os.Stat(name)
	if err != nil {
		return err
	}
	return nil
}

func (d *systemDepot) getFile(path string) (*file, error) {
	if err := d.check(path); err != nil {
		return nil, err
	}
	fi, err := os.Stat(d.path(path))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(d.path(path))
	return &file{fi, b}, err
}

func (d *systemDepot) path(name string) string {
	return filepath.Join(d.dirPath, name)
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType = "CERTIFICATE"
)

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

// load an encrypted private key from disk
func loadKey(data []byte, password []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	b, err := x509.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(b)
}

// load an encrypted private key from disk
func loadCert(data []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

type Values struct {
	Name         string
	AllowTime    int
	SerialNumber *big.Int
	NotBefore    string
	NotAfter     string
	Pem          string
}

//serial 作成　ここ変える このままでもいいんちゃう？
func (d *fileDepot) Serial() (*big.Int, error) {
	name := d.path("serial")
	s := big.NewInt(2)
	if err := d.check("serial"); err != nil {
		// assuming it doesnt exist, create
		if err := d.writeSerial(s); err != nil {
			return nil, err
		}
		return s, nil
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	r := bufio.NewReader(file)
	data, err := r.ReadString('\r')
	if err != nil && err != io.EOF {
		return nil, err
	}
	data = strings.TrimSuffix(data, "\r")
	data = strings.TrimSuffix(data, "\n")
	//
	serial, ok := s.SetString(data, 16)
	if !ok {
		return nil, errors.New("could not convert " + string(data) + " to serial number")
	}
	return serial, nil
}

func Destribute(name string,allowTime int, cert *x509.Certificate) (bool, error) {
	values := Values{Name: name, AllowTime: allowTime, SerialNumber: cert.SerialNumber, NotBefore: cert.NotBefore.String(), NotAfter: cert.NotAfter.String(), Pem: string(pemCert(cert.Raw))}
	values_json, err := json.Marshal(values)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Print("\n")
		return false, err
	}
	// タイムアウトを30秒に指定してClient構造体を生成
	cli := &http.Client{Timeout: time.Duration(30) * time.Second}
	// 生成したURLを元にRequest構造体を生成
	URL := os.Getenv("URL_CERT")
	req, _ := http.NewRequest("POST", URL, bytes.NewBuffer(values_json))
	// リクエストにヘッダ情報を追加
	token := os.Getenv("JWT_TOKEN")
	req.Header.Add("authorization", "Bearer"+" "+token)
	req.Header.Set("Content-Type", "application/json")
	// POSTリクエスト発行
	rsp, err := cli.Do(req)
	if err != nil {
		fmt.Print("debug2:POSTリクエスト発行\n")
		fmt.Println(err)
		fmt.Print("\n")
		fmt.Print("unsupported protocol schemeの時は環境変数が設定されているかをチェック\n")
		return false, err
	}
	if rsp.StatusCode == 200 {
		return true, nil
	}
	body, _ := ioutil.ReadAll(rsp.Body)
	fmt.Print("debug3:エラー！レスポンスを取得し出力\n")
	fmt.Println(string(body))
	fmt.Print("\n")
	return false, errors.New(string(body))
}






