package server

import (
	"context"
	"os"
	"testing"

	"github.com/vine-io/rbac/adpter"
	"github.com/vine-io/rbac/api"
	"github.com/vine-io/vine"
	vclient "github.com/vine-io/vine/core/client"
	"github.com/vine-io/vine/core/client/grpc"
	vapi "github.com/vine-io/vine/lib/api"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	dsn  = "server.sqlite.db"
	name = "rbac"
	addr = "127.0.0.1:33444"
)

func newDBInstance(t *testing.T) *gorm.DB {

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}

	return db
}

func newRBACServerWithApt(t *testing.T) *RBACServer {
	db := newDBInstance(t)

	apt, err := adpter.NewGormAdapter(db)
	if err != nil {
		t.Fatal(err)
	}

	s := vine.NewService(vine.Name(name), vine.Address(addr))
	_ = s.Init()

	server, err := NewRBACServerWithApt(s, apt)
	if err != nil {
		t.Fatal(err)
	}

	if err = api.RegisterRBACServiceHandler(s.Server(), server); err != nil {
		t.Fatal(err)
	}

	if err = s.Server().Start(); err != nil {
		t.Fatal(err)
	}

	return server
}

func TestNewRBACServerWithApt(t *testing.T) {
	newRBACServerWithApt(t)
	os.Remove(dsn)
}

func TestRBACServer_AddPolicy(t *testing.T) {
	_ = newRBACServerWithApt(t)
	ctx := context.TODO()
	defer os.Remove(dsn)

	conn := grpc.NewClient()
	client := api.NewRBACService(name, conn)
	user := "lack"
	ep := &vapi.Endpoint{
		Name:   "object",
		Method: []string{"read"},
	}
	_, err := client.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy: &api.Policy{Sub: user, Endpoint: ep},
	}, vclient.WithAddress(addr))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AddGroupPolicy(ctx, &api.AddGroupPolicyRequest{
		Subject: &api.Subject{
			Ptype: api.PType_ROLE,
			User:  "lack",
			Group: "admin",
		},
	}, vclient.WithAddress(addr))
	if err != nil {
		t.Fatal(err)
	}

	rsps, err := client.GetPolicy(ctx, &api.GetPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rsps.Policies, rsps.Subjects)

	_, err = client.DelGroupPolicy(ctx, &api.DelGroupPolicyRequest{
		Subject: &api.Subject{
			Ptype: api.PType_ROLE,
			User:  "lack",
			Group: "admin",
		},
	}, vclient.WithAddress(addr))
	if err != nil {
		t.Fatal(err)
	}

	rsp, err := client.Enforce(ctx, &api.EnforceRequest{
		Policy: &api.Policy{Sub: user, Endpoint: ep},
	}, vclient.WithAddress(addr))

	if err != nil || !rsp.Result {
		t.Fatal("enforce failed")
	}
}
