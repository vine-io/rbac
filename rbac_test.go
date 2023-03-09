package rbac

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/vine-io/rbac/adapter"
	"github.com/vine-io/rbac/api"
	vapi "github.com/vine-io/vine/lib/api"
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

	apt, err := adapter.NewGormAdapter(db)
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

	ctx := context.TODO()

	r.AddPolicy(ctx, &api.Policy{
		Sub: "lack",
		Endpoint: &vapi.Endpoint{
			Method: []string{"read"},
			Entity: "user",
		},
	})
	r.AddPolicy(ctx, &api.Policy{
		Sub: "lack",
		Endpoint: &vapi.Endpoint{
			Method: []string{"write"},
			Entity: "user",
		},
	})
	r.AddPolicy(ctx, &api.Policy{
		Sub: "lack",
		Endpoint: &vapi.Endpoint{
			Method: []string{"list"},
			Entity: "user",
		},
	})

	r.AddGroupPolicy(ctx, &api.Subject{
		Ptype: api.PType_ROLE,
		User:  "lack",
		Group: "administrator",
	})

	r.AddGroupPolicy(ctx, &api.Subject{
		Ptype: api.PType_GROUP,
		User:  "lack",
		Group: "aa",
	})

	_, err = r.Enforce(ctx, &api.Policy{
		Sub: "lack",
		Endpoint: &vapi.Endpoint{
			Entity: "user",
			Method: []string{"read"},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	policy, subjects := r.GetPolicy(ctx)
	t.Log(policy)
	t.Log(subjects)
}
