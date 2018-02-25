package main

import (
	"log"

	"github.com/ogier/pflag"
	"github.com/superp00t/phoxy2"

	_ "github.com/go-sql-driver/mysql"
)

var (
	driver = pflag.StringP("driver", "d", "mysql", "SQL driver (must be imported pre-compile)")
	source = pflag.StringP("source", "s", "root:root@/phoxy2?charset=utf8", "SQL database URL")
	addr   = pflag.StringP("listen", "l", "localhost:40600", "HTTP listen address")
)

func main() {
	pflag.Parse()

	log.Fatal(phoxy2.RunServer(phoxy2.Opts{
		Driver:  *driver,
		URL:     *source,
		Address: *addr,
	}))
}
