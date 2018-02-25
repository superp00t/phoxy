package phoxy2

import (
	"net/http"

	"github.com/dchest/captcha"

	"github.com/go-xorm/xorm"
	"github.com/gorilla/mux"
)

type Server struct {
	DB *xorm.Engine

	SessionList map[int64]*Session
}

type Opts struct {
	Address     string
	Driver, URL string
	AppPath     string
}

func RunServer(o Opts) error {
	s := new(Server)
	var err error
	s.DB, err = xorm.NewEngine(o.Driver, o.URL)
	if err != nil {
		return err
	}

	// Structs to be synced with SQL database
	schemas := []interface{}{
		new(Sub),
		new(EtcData),
		new(SpamData),
		new(Account),
		new(Token),
		new(SessionListing),
	}

	for _, v := range schemas {
		err := s.DB.Sync2(v)
		if err != nil {
			return err
		}
	}

	// Clear session list upon startup
	s.DB.Delete(new(SessionListing))

	r := mux.NewRouter()
	r.PathPrefix("/app/").Handler(http.StripPrefix("/app/", http.FileServer(http.Dir("/home/jjj/cd2/public/"))))

	r.HandleFunc("/ws", s.NewSession)

	z := r.PathPrefix("/zdb/").Subrouter()
	z.HandleFunc("/user_exists/{user}", s.CheckSpam(1, s.UserExists))
	z.HandleFunc("/avatar/{img}.png", s.CheckSpam(1, s.GetAvatar))
	z.HandleFunc("/login", s.CheckSpam(800, s.HandleLogin))
	z.HandleFunc("/register", s.CheckSpam(10, s.HandleRegister))
	z.HandleFunc("/new_captcha", s.CheckSpam(400, s.NewCaptcha))
	z.PathPrefix("/captcha/").Handler(captcha.Server(captcha.StdWidth, captcha.StdHeight))

	return http.ListenAndServe(o.Address, &cors{r})
}

type cors struct {
	h http.Handler
}

func (c *cors) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	c.h.ServeHTTP(rw, r)
}
