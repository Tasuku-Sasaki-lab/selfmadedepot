package system

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// New SystemDepot returns a new cert depot.
func NewSystemDepot(path string) (*systemDepot, error) {
	return &systemDepot{dirPath: path}, nil
}

type systemDepot struct {
	dirPath string
}

func (d *systemDepot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
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
	certificatePEMBlockType   = "CERTIFICATE"
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
	Cert      *x509.Certificate
	Name      string
	AllowTime int
	Pem       string
}

// file permissions
const (
	serialPerm = 0400
)

func (d *systemDepot) writeSerial(serial *big.Int) error {
	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}
	name := d.path("serial")
	os.Remove(name)

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, serialPerm)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf("%x\n", serial.Bytes())); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

//serial 作成　ここ変える このままでもいいんちゃう？ // ここランダムにする
func (d *systemDepot) Serial() (*big.Int, error) {
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	var max *big.Int = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil)
	// Generate cryptographically strong pseudo-random between [0, max)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	// この2をランダムにすればいいのか？　checkに引っ掛からなかった場合を整理しよう
	name := d.path("serial")
	s := big.NewInt(n)
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

func (d *systemDepot) Destribute(name string, allowTime int, cert *x509.Certificate) (bool, error) {
	values := Values{Cert: cert, Name: name, AllowTime: allowTime, Pem: string(pemCert(cert.Raw))}
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
