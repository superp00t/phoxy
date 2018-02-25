package phoxy2

import (
	"log"
	"net/http"
	"strings"

	"github.com/superp00t/etc"
	"golang.org/x/net/websocket"
)

// Track server session state
type Session struct {
	Username string

	entry int64
	srv   *Server
	ws    *websocket.Conn
}

func (s *Session) HandleBuffer(b *etc.Buffer) {
	op := b.ReadUint16()

	switch op {
	case CMD_FETCH_DATA:
		s.ServeData(b)
		return
	case CMD_STORE_DATA:
		s.StoreData(b)
		return
	}
}

func (s *Session) ServeData(b *etc.Buffer) {
	// request id
	rid := b.ReadBytes(16)
	key := b.ReadCString()

	if key == "@me:(roster)" {
		s.ServeRoster(rid)
		return
	}

	sk := strings.Split(key, ":")
	if len(sk) != 2 {
		log.Println("User attempted BAD key format.")
		return
	}

	u := sk[0]
	me := false
	if u == "@me:" {
		u = s.Username
		me = true
	}

	var l []EtcData
	s.srv.DB.Where("account = ?", u).Where("data_key = ?", key).Find(&l)
	if len(l) == 0 {
		b := newMsg(CMD_REQUEST_RESPONSE)
		b.Write(rid)
		b.WriteByte(DATA_NOT_FOUND)
		b.WriteByte(FLAG_PUBLIC_ACCESS | FLAG_PRIVATE_ACCESS | FLAG_PEER_ACCESS)
		s.Send(b)
		return
	}

	dat := l[0]

	if !me && (dat.Flags&FLAG_PUBLIC_ACCESS) == 0 {
		b := newMsg(CMD_REQUEST_RESPONSE)
		b.Write(rid)
		b.WriteByte(DATA_UNAUTHORIZED)
		b.WriteByte(dat.Flags)
		s.Send(b)
		return
	}

	be := newMsg(CMD_REQUEST_RESPONSE)
	be.Write(rid)
	be.WriteByte(DATA_FOUND)
	be.WriteByte(dat.Flags)
	be.Write(dat.Data)
	s.Send(be)
}

func (s *Session) StoreData(b *etc.Buffer) {
	b.ReadBytes(16)
	key := b.ReadCString()
	data := b.ReadLimitedBytes()

	s.srv.DB.Where("account = ?", s.Username).Where("data_key = ?", key).Delete(new(EtcData))
	s.srv.DB.Insert(&EtcData{
		Account: s.Username,
		Key:     key,
		Data:    data,
	})
}

func (s *Session) SendBuffer(b []byte) {
	websocket.Message.Send(s.ws, b)
}

func (s *Session) Send(b *etc.Buffer) {
	s.SendBuffer(b.Bytes())
}

func (s *Session) ReadData() (*etc.Buffer, error) {
	var m []byte
	err := websocket.Message.Receive(s.ws, &m)
	if err != nil {
		return nil, err
	}

	return etc.MkBuffer(m), nil
}

func (s *Session) ServeRoster(rid []byte) {
	b := newMsg(CMD_REQUEST_RESPONSE)
	b.Write(rid)
	b.WriteByte(DATA_FOUND)
	b.WriteByte(FLAG_PRIVATE_ACCESS)

	var subs []Sub
	s.srv.DB.Where("user_from = ?", s.Username).Find(&subs)

	for _, v := range subs {
		b.WriteCString(v.To)
	}
	s.Send(b)
}

func (s *Session) Destroy() {
	s.srv.DB.Where("entry = ?", s.entry).Delete(new(SessionListing))
	delete(s.srv.SessionList, s.entry)
}

func newMsg(op uint16) *etc.Buffer {
	b := etc.NewBuffer()
	b.WriteUint16(op)
	return b
}

func (s *Server) NewSession(rw http.ResponseWriter, r *http.Request) {
	var t []Token
	s.DB.Where("token = ?", r.URL.Query().Get("t")).Find(&t)
	if len(t) == 0 {
		unauth(rw, r)
		return
	}

	srv := websocket.Server{Handler: websocket.Handler(func(ws *websocket.Conn) {
		sesh := &Session{
			Username: t[0].Account,
			srv:      s,
			ws:       ws,
		}

		for {
			buf, err := sesh.ReadData()
			if err != nil {
				log.Println("Error reading from client ", sesh.Username, " ", err)
				break
			}

			sesh.HandleBuffer(buf)
		}

		sesh.Destroy()
	})}

	srv.ServeHTTP(rw, r)
}

func unauth(rw http.ResponseWriter, r *http.Request) {
	http.Error(rw, "unauthorized", http.StatusUnauthorized)
}
