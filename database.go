package phoxy2

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

type Sub struct {
	User string `xorm:"user_from"`
	To   string `xorm:"user_to"`
}

type EtcData struct {
	Account string `xorm:"account"`
	Flags   uint8  `xorm:"flags"`
	Key     string `xorm:"data_key"`
	Data    []byte `xorm:"data_bytes"`
}

type Account struct {
	Id           int64
	Account      string `xorm:"account"`
	Level        int32  `xorm:"level"`
	PasswordHash string `xorm:"password_hash"`
}

type SpamData struct {
	Id          int64
	IP          uint32 `xorm:"ip_address"`
	Score       int64  `xorm:"score"`
	Init        int64  `xorm:"init_date"`
	LastUpdated int64  `xorm:"last_updated_date"`
}

type Token struct {
	Account string `xorm:"account"`
	Token   string `xorm:"token"`
	Created int64  `xorm:"created_date"`
}

type SessionListing struct {
	Entry     int64  `xorm:"entry"`
	Account   string `xorm:"account"`
	Joined    int64  `xorm:"joined_date"`
	UserAgent string `xorm:"useragent"`
	IP        uint32 `xorm:"ip_address"`
	Token     string `xorm:"token"`
}

func (s *Server) Avatar(user string) []byte {
	var k []EtcData
	s.DB.Where("account = ?", user).Where("data_key = ?", "avatar").Find(&k)
	if k == nil {
		return nil
	}

	return k[0].Data
}

func (s *Server) GetAvatar(rw http.ResponseWriter, r *http.Request) {
	path := mux.Vars(r)["img"]
	b := s.Avatar(path)
	if b == nil {
		http.Error(rw, "not found", 404)
		return
	}

	rw.Write(b)
}

func ipToInt(ip string) (uint32, error) {
	b := make([]byte, 4)
	d := strings.Split(ip, ".")
	if len(d) != 4 {
		return 0, fmt.Errorf("Invalid ipv4")
	}

	for i, v := range d {
		c, err := strconv.ParseInt(v, 10, 8)
		if err != nil {
			return 0, err
		}

		b[i] = uint8(c)
	}

	return binary.LittleEndian.Uint32(b), nil
}

func intToIp(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
