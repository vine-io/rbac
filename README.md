# usage

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/vine-io/rbac"
	"github.com/vine-io/rbac/adpter"
	"github.com/vine-io/vine/lib/api"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const dsn = "rbac.sqlite.db"

func main() {
	db, err := gorm.Open(sqlite.Open(dsn))
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(dsn)

	apt, err := adpter.NewGormAdapter(db)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := rbac.NewConfig(apt)
	if err != nil {
		log.Fatal(err)
	}

	r, err := rbac.NewRBAC(cfg)
	if err != nil {
		log.Fatal(err)
	}

	r.Enforce(context.TODO(), "user", &api.Endpoint{
		Name:   "object",
		Entity: "object",
		Method: []string{"read"},
	})
}

```