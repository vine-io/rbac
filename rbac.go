package rbac

import (
	"context"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/vine-io/vine/lib/api"
)

type PType string

const (
	Role   PType = "g"
	Group  PType = "g2"
	Policy PType = "p"
)

type Subject struct {
	PType PType  `json:"ptype"`
	User  string `json:"user"`
	Group string `json:"group"`
}

type RBAC interface {
	AddPolicy(ctx context.Context, sub string, endpoint *api.Endpoint) error
	DelPolicy(ctx context.Context, sub string, endpoint *api.Endpoint) error
	AddGroupPolicy(ctx context.Context, subject *Subject) error
	DelGroupPolicy(ctx context.Context, subject *Subject) error
	Enforce(ctx context.Context, sub string, endpoint *api.Endpoint) (bool, error)
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
		m, err := model.NewModelFromString(DefaultAdminName)
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
	e.EnableAutoSave(true)

	if err = e.LoadPolicy(); err != nil {
		return nil, err
	}

	return &rbac{Config: cfg, e: e}, nil
}
func (r *rbac) AddPolicy(ctx context.Context, sub string, endpoint *api.Endpoint) error {
	obj, act := parseEndpoint(endpoint)

	ok, err := r.e.AddPolicy(ctx, sub, obj, act)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if ok {
		return ErrAlreadyExists
	}

	return nil
}

func (r *rbac) DelPolicy(ctx context.Context, sub string, endpoint *api.Endpoint) error {
	obj, act := parseEndpoint(endpoint)

	ok, err := r.e.RemovePolicy(ctx, sub, obj, act)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if ok {
		return ErrNotFound
	}

	return nil
}

func (r *rbac) AddGroupPolicy(ctx context.Context, subject *Subject) error {

	ok, err := r.e.AddGroupingPolicy(subject.PType, subject.User, subject.Group)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if ok {
		return ErrAlreadyExists
	}

	return nil
}

func (r *rbac) DelGroupPolicy(ctx context.Context, subject *Subject) error {
	ok, err := r.e.RemoveGroupingPolicy(subject.PType, subject.User, subject.Group)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if ok {
		return ErrNotFound
	}

	return nil
}

func (r *rbac) Enforce(ctx context.Context, sub string, endpoint *api.Endpoint) (bool, error) {

	obj, act := parseEndpoint(endpoint)

	ok, err := r.e.Enforce(sub, obj, act)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	return ok, nil
}
