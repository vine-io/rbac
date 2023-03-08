package rbac

import (
	"log"
	"os"
	"testing"

	"github.com/vine-io/rbac/adpter"
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

	_ = r
}
