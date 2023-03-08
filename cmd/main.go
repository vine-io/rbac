package main

import (
	"log"

	"github.com/vine-io/rbac/adpter"
	"github.com/vine-io/rbac/api"
	"github.com/vine-io/rbac/server"
	"github.com/vine-io/vine"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	dsn = "server.sqlite.db"
)

func main() {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	apt, err := adpter.NewGormAdapter(db)
	if err != nil {
		log.Fatal(err)
	}

	s := vine.NewService()
	if err = s.Init(); err != nil {
		log.Fatal(err)
	}

	rbac, err := server.NewRBACServerWithApt(s, apt)
	if err != nil {
		log.Fatal(err)
	}

	if err = api.RegisterRBACServiceHandler(s.Server(), rbac); err != nil {
		log.Fatal(err)
	}

	if err = s.Run(); err != nil {
		log.Fatal(err)
	}
}
