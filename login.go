package phoxy2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dchest/captcha"
	"github.com/gorilla/mux"

	"github.com/superp00t/etc"
)

func (s *Server) HandleLogin(rw http.ResponseWriter, r *http.Request) {
	e := etc.NewBuffer()
	io.Copy(e, r.Body)

	username := e.ReadCString()

	hash := e.ReadBytes(64)
	salt := e.ReadBytes(32)

	log.Println("User attempted login: ", username)
	o := etc.NewBuffer()

	var a []Account
	s.DB.Where("account = ?", username).Find(&a)
	if a == nil {
		o.WriteByte(AUTH_FAIL)
		rw.Write(o.Bytes())
		return
	}

	ac := a[0]

	aH := etc.NewBuffer()
	b, _ := hex.DecodeString(ac.PasswordHash)
	aH.Write(b)
	aH.Write(salt)

	ok := bytes.Equal(aH.Sha512Digest(), hash)

	if !ok {
		log.Println("User challenge hash did not match.")
		o.WriteByte(AUTH_FAIL)
		rw.Write(o.Bytes())
		return
	}

	token := s.GenerateSecureToken(username)
	o.WriteByte(AUTH_SUCCESS)
	o.WriteCString(token)
	rw.Write(o.Bytes())
}

const tokenKeys = "abcdefghijklmnopqrstuvwxyz0123456789_-:."
const tokenSize = 32

func (s *Server) GenerateSecureToken(u string) string {
	buf := ""
	tk := []rune(tokenKeys)
	spc := len(tk)

	for i := 0; i < tokenSize; i++ {
		d := secureIntn(0, spc)
		buf += string(tokenKeys[d])
	}

	s.DB.Insert(&Token{
		Account: u,
		Token:   buf,
		Created: time.Now().Unix(),
	})

	return buf
}

func secureIntn(min, max int) int {
	bi, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(bi.Int64())
}

func (s *Server) HandleRegister(rw http.ResponseWriter, r *http.Request) {
	e := etc.NewBuffer()
	io.Copy(e, r.Body)

	captchaID := e.ReadCString()
	captchaSolution := e.ReadCString()
	username := strings.ToLower(e.ReadCString())
	hashData := e.ReadBytes(64)

	if !isValidName(username) {
		o := etc.NewBuffer()
		o.WriteByte(NAME_INVALID)
		rw.Write(o.Bytes())
		return
	}

	if s.UsernameInUse(username) {
		o := etc.NewBuffer()
		o.WriteByte(NAME_IN_USE)
		rw.Write(o.Bytes())
		return
	}

	if !captcha.VerifyString(captchaID, captchaSolution) {
		o := etc.NewBuffer()
		o.WriteByte(CAPTCHA_FAIL)
		rw.Write(o.Bytes())
		return
	}

	s.DB.Insert(&Account{
		Account:      username,
		Level:        1,
		PasswordHash: hex.EncodeToString(hashData),
	})

	o := etc.NewBuffer()
	o.WriteByte(REGISTER_SUCCESS)
	rw.Write(o.Bytes())
}

func (s *Server) UsernameInUse(st string) bool {
	var d []Account
	s.DB.Where("binary account = ?", st).Find(&d)

	return len(d) != 0
}

func (s *Server) NewCaptcha(rw http.ResponseWriter, r *http.Request) {
	b := etc.NewBuffer()
	ns := captcha.New()
	log.Println(ns)
	b.WriteCString(ns)
	rw.Write(b.Bytes())
}

func isValidName(n string) bool {
	b, err := regexp.MatchString("^[a-z0-9_]*$", n)
	if err != nil {
		panic(err)
	}

	return b
}

func (s *Server) UserExists(rw http.ResponseWriter, r *http.Request) {
	var rs uint8
	if s.UsernameInUse(strings.ToLower(mux.Vars(r)["user"])) {
		rs++
	}

	rw.Write([]byte{rs})
}
