package server

import (
	"context"

	"github.com/casbin/casbin/v2/persist"
	"github.com/vine-io/rbac"
	"github.com/vine-io/rbac/api"
	"github.com/vine-io/vine"
	verrs "github.com/vine-io/vine/lib/errors"
)

type RBACServer struct {
	vine.Service
	r rbac.RBAC
}

func NewRBACServerWithApt(s vine.Service, apt persist.Adapter) (*RBACServer, error) {
	cfg, err := rbac.NewConfig(apt)
	if err != nil {
		return nil, err
	}
	r, err := rbac.NewRBAC(cfg)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	server := &RBACServer{
		Service: s,
		r:       r,
	}

	return server, nil
}

func (s *RBACServer) GetPolicy(ctx context.Context, req *api.GetPolicyRequest, rsp *api.GetPolicyResponse) (err error) {
	rsp.Policies, rsp.Subjects = s.r.GetPolicy(ctx)
	return
}

func (s *RBACServer) AddPolicy(ctx context.Context, req *api.AddPolicyRequest, rsp *api.AddPolicyResponse) (err error) {
	if req.Policy == nil {
		return verrs.BadRequest(s.Name(), "missing policy")
	}

	err = s.r.AddPolicy(ctx, req.Policy)
	return
}

func (s *RBACServer) DelPolicy(ctx context.Context, req *api.DelPolicyRequest, rsp *api.DelPolicyResponse) (err error) {
	if req.Policy == nil {
		return verrs.BadRequest(s.Name(), "missing policy")
	}

	err = s.r.DelPolicy(ctx, req.Policy)
	return
}

func (s *RBACServer) AddGroupPolicy(ctx context.Context, req *api.AddGroupPolicyRequest, rsp *api.AddGroupPolicyResponse) (err error) {
	if req.Subject == nil {
		return verrs.BadRequest(s.Name(), "missing sub")
	}

	err = s.r.AddGroupPolicy(ctx, req.Subject)
	return
}

func (s *RBACServer) DelGroupPolicy(ctx context.Context, req *api.DelGroupPolicyRequest, rsp *api.DelGroupPolicyResponse) (err error) {
	if req.Subject == nil {
		return verrs.BadRequest(s.Name(), "missing sub")
	}

	err = s.r.DelGroupPolicy(ctx, req.Subject)
	return
}

func (s *RBACServer) Enforce(ctx context.Context, req *api.EnforceRequest, rsp *api.EnforceResponse) (err error) {
	if req.Policy == nil {
		return verrs.BadRequest(s.Name(), "missing policy")
	}

	rsp.Result, err = s.r.Enforce(ctx, req.Policy)
	return
}
