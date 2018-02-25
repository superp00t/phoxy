package phoxy2

import (
	"log"
	"net/http"
	"time"
)

const (
	scoreLimit       = 0x10000
	antispamInterval = 2 * time.Hour

	localhost = 0x100007f
)

func (s *Server) CheckSpam(cost int64, fn http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ip, err := ipToInt(r.Header.Get("X-Real-IP"))
		if err != nil {
			ip = localhost
			// tmr(rw, r)
			// return
		}

		if ip == localhost {
			log.Println("User connected from localhost, bypassing spam filter")
			fn(rw, r)
			return
		}

		var sd []SpamData
		s.DB.Where("ip_address = ?", ip).Find(&sd)
		if len(sd) == 0 {
			s.DB.Insert(&SpamData{
				IP:          ip,
				Score:       100,
				Init:        time.Now().Unix(),
				LastUpdated: time.Now().Unix(),
			})

			fn(rw, r)
			return
		}

		// If spam record is old, clear records and let user in
		lu := time.Unix(sd[0].LastUpdated, 0)
		if (time.Now().UnixNano() - antispamInterval.Nanoseconds()) > lu.UnixNano() {
			// Clear old records
			s.UpdateSpam(ip, 0)
			fn(rw, r)
			return
		}

		if sd[0].Score > scoreLimit {
			tmr(rw, r)
			return
		}

		s.UpdateSpam(ip, sd[0].Score+cost)
		fn(rw, r)
	})
}

func (s *Server) UpdateSpam(i uint32, score int64) {
	var sd []SpamData
	s.DB.Where("ip_address = ?", i).Find(&sd)
	if len(sd) == 0 {
		return
	}

	y := sd[0]
	y.LastUpdated = time.Now().Unix()
	y.Score = score

	s.DB.Id(y.Id).Update(y)
}

func tmr(rw http.ResponseWriter, r *http.Request) {
	http.Error(rw, "too many requests", http.StatusTooManyRequests)
}
