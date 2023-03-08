package rbac

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/vine-io/rbac/adpter"
	"github.com/vine-io/vine/lib/api"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const dsn = "rbac.sqlite.db"

func TestNewRBAC(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(dsn))
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(dsn)

	apt, err := adpter.NewGormAdapter(db)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := NewConfig(apt)
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewRBAC(cfg)
	if err != nil {
		t.Fatal(err)
	}

	r.Enforce(context.TODO(), "user", &api.Endpoint{
		Name:   "object",
		Entity: "object",
		Method: []string{"read"},
	})
}
