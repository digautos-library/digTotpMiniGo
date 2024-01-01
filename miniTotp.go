/**
 *  Copyright dig.autos 2024
 *
 *  reference: github.com/pquerna/otp/totp
 *
 */
 package digTotpMiniGo

 import (
	 "crypto/hmac"
	 "crypto/md5"
	 "crypto/sha1"
	 "crypto/sha256"
	 "crypto/sha512"
	 "encoding/base32"
	 "encoding/binary"
	 "fmt"
	 "hash"
	 "math"
	 "strings"
	 "time"
 )
 
 type TAlgorithm int
 
 const (
	 // AlgorithmSHA1 should be used for compatibility with Google Authenticator.
	 //
	 // See https://github.com/pquerna/otp/issues/55 for additional details.
	 AlgorithmSHA1 TAlgorithm = iota
	 AlgorithmSHA256
	 AlgorithmSHA512
	 AlgorithmMD5
 )
 
 type CDigMiniTotp struct {
	 passcodeLength int
	 algorithm      TAlgorithm
 }
 
 func NewDigMiniTotpForGithub() *CDigMiniTotp {
	 return NewDigMiniTotp(6, AlgorithmSHA1)
 }
 func NewDigMiniTotp(passcodeLength int, algo TAlgorithm) *CDigMiniTotp {
	 iLen1 := passcodeLength
	 if iLen1 <= 6 {
		 iLen1 = 6
	 } else {
		 iLen1 = 8
	 }
	 return &CDigMiniTotp{passcodeLength: iLen1, algorithm: algo}
 }
 
 // GenerateTotpCodeNow returns TOTP code for current time.
 func (instSelf *CDigMiniTotp) GenerateTotpCodeNow(secretkey string) (string, error) {
	 return instSelf.GenerateTotpCode(secretkey, time.Now())
 }
 func (instSelf *CDigMiniTotp) GenerateTotpCode(secretKey string, baseTime time.Time) (string, error) {
	 counter := uint64(math.Floor(float64(baseTime.Unix()) / float64(30)))
	 secret := strings.TrimSpace(secretKey)
	 if n := len(secret) % 8; n != 0 {
		 secret = secret + strings.Repeat("=", 8-n)
	 }
	 secret = strings.ToUpper(secret)
 
	 secretBytes, err := base32.StdEncoding.DecodeString(secret)
	 if err != nil {
		 return "", err
	 }
	 buf := make([]byte, 8)
	 mac := hmac.New(instSelf.getHashCode, secretBytes)
	 binary.BigEndian.PutUint64(buf, counter)
 
	 mac.Write(buf)
	 sum := mac.Sum(nil)
 
	 offset := sum[len(sum)-1] & 0xf
	 value := int64(((int(sum[offset]) & 0x7f) << 24) |
		 ((int(sum[offset+1] & 0xff)) << 16) |
		 ((int(sum[offset+2] & 0xff)) << 8) |
		 (int(sum[offset+3]) & 0xff))
 
	 l := instSelf.passcodeLength
	 mod := int32(value % int64(math.Pow10(l)))
 
	 return instSelf.codeFormat(mod), nil
 }
 func (instSelf *CDigMiniTotp) codeFormat(code int32) string {
	 f := fmt.Sprintf("%%0%dd", instSelf.passcodeLength)
	 return fmt.Sprintf(f, code)
 }
 func (instSelf *CDigMiniTotp) getHashCode() hash.Hash {
	 switch instSelf.algorithm {
	 case AlgorithmSHA1:
		 return sha1.New()
	 case AlgorithmSHA256:
		 return sha256.New()
	 case AlgorithmSHA512:
		 return sha512.New()
	 case AlgorithmMD5:
		 return md5.New()
	 }
 
	 return sha1.New()
 }
 