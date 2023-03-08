package rbac

import (
	"context"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/vine-io/rbac/api"
	vapi "github.com/vine-io/vine/lib/api"
)

type RBAC interface {
	AddPolicy(ctx context.Context, sub string, endpoint *vapi.Endpoint) error
	DelPolicy(ctx context.Context, sub string, endpoint *vapi.Endpoint) error
	AddGroupPolicy(ctx context.Context, subject *api.Subject) error
	DelGroupPolicy(ctx context.Context, subject *api.Subject) error
	Enforce(ctx context.Context, sub string, endpoint *vapi.Endpoint) (bool, error)
}

var _ RBAC = (*rbac)(nil)

type Config struct {
	adp       persist.Adapter
	model     model.Model
	adminName string
}

func NewConfig(adapter persist.Adapter) (Config, error) {
	cfg := Config{
		adp: adapter,
	}

	if err := cfg.configure(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) configure() error {
	if c.adminName == "" {
		c.adminName = DefaultAdminName
	}

	if c.model == nil {
		m, err := model.NewModelFromString(DefaultModel)
		if err != nil {
			return err
		}
		c.model = m
	}

	return nil
}

type rbac struct {
	Config

	e *casbin.Enforcer
}

func NewRBAC(cfg Config) (RBAC, error) {
	if err := cfg.configure(); err != nil {
		return nil, fmt.Errorf("check config: %v", err)
	}

	e, err := casbin.NewEnforcer(cfg.model, cfg.adp)
	if err != nil {
		return nil, err
	}
	if err = cfg.adp.SavePolicy(e.GetModel()); err != nil {
		return nil, err
	}
	e.ClearPolicy()
	e.EnableAutoSave(true)

	if err = e.LoadPolicy(); err != nil {
		return nil, err
	}

	return &rbac{Config: cfg, e: e}, nil
}
func (r *rbac) AddPolicy(ctx context.Context, sub string, endpoint *vapi.Endpoint) error {
	obj, act := parseEndpoint(endpoint)

	ok, err := r.e.AddPolicy(sub, obj, act)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrAlreadyExists
	}

	return nil
}

func (r *rbac) DelPolicy(ctx context.Context, sub string, endpoint *vapi.Endpoint) error {
	obj, act := parseEndpoint(endpoint)

	ok, err := r.e.RemovePolicy(sub, obj, act)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrNotFound
	}

	return nil
}

func (r *rbac) AddGroupPolicy(ctx context.Context, subject *api.Subject) error {

	ok, err := r.e.AddGroupingPolicy(string(subject.PType), subject.User, subject.Group)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrAlreadyExists
	}

	return nil
}

func (r *rbac) DelGroupPolicy(ctx context.Context, subject *api.Subject) error {
	ok, err := r.e.RemoveGroupingPolicy(string(subject.PType), subject.User, subject.Group)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrNotFound
	}

	return nil
}

func (r *rbac) Enforce(ctx context.Context, sub string, endpoint *vapi.Endpoint) (bool, error) {

	obj, act := parseEndpoint(endpoint)

	ok, err := r.e.Enforce(sub, obj, act)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	return ok, nil
}
