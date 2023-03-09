package server

import (
	"context"
	"os"
	"testing"

	"github.com/vine-io/rbac/adapter"
	"github.com/vine-io/rbac/api"
	"github.com/vine-io/vine"
	vclient "github.com/vine-io/vine/core/client"
	"github.com/vine-io/vine/core/client/grpc"
	vapi "github.com/vine-io/vine/lib/api"
	clientv3 "go.etcd.io/etcd/client/v3"
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

	apt, err := adapter.NewGormAdapter(db)
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

func newRBACServerWithEtcd(t *testing.T) *RBACServer {
	conn, err := clientv3.New(clientv3.Config{
		Endpoints: []string{"127.0.0.1:2379"},
	})

	if err != nil {
		t.Fatal(err)
	}

	apt, err := adapter.NewEtcdAdapter(conn)
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

func TestNewRBACServerWithEtcdApt(t *testing.T) {
	newRBACServerWithEtcd(t)
	os.Remove(dsn)
}

func testServer(t *testing.T) {
	ctx := context.TODO()
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

	rsps, err := client.GetAllPolicies(ctx, &api.GetAllPoliciesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rsps.Policies, rsps.Subjects)

	rr, err := client.GetPolicies(ctx, &api.GetPoliciesRequest{Sub: "lack"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rr.Policies)

	rs, err := client.GetGroupPolicies(ctx, &api.GetGroupPoliciesRequest{Ptype: api.PType_ROLE, Sub: "lack"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rs.Subjects)

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

func TestRBACServer_AddPolicy(t *testing.T) {
	_ = newRBACServerWithApt(t)
	defer os.Remove(dsn)

	testServer(t)
}

func TestRBACServerEtcd_AddPolicy(t *testing.T) {
	_ = newRBACServerWithEtcd(t)

	testServer(t)
}
