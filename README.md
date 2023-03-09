# usage

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/vine-io/rbac"
	"github.com/vine-io/rbac/adapter"
	api "github.com/vine-io/rbac/api"
	vapi "github.com/vine-io/vine/lib/api"
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

	r.Enforce(context.TODO(), &api.Policy{
		Sub: "lack",
		Endpoint: &vapi.Endpoint{
			Entity: "user",
			Method: []string{"read"},
		},
	})
}

```