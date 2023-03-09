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
	GetAllPolicies(ctx context.Context) ([]*api.Policy, []*api.Subject)
	GetPolicies(ctx context.Context, sub string) []*api.Policy
	AddPolicy(ctx context.Context, p *api.Policy) error
	DelPolicy(ctx context.Context, p *api.Policy) error
	GetGroupPolicies(ctx context.Context, p api.PType, sub string) []*api.Subject
	AddGroupPolicy(ctx context.Context, subject *api.Subject) error
	DelGroupPolicy(ctx context.Context, subject *api.Subject) error
	Enforce(ctx context.Context, p *api.Policy) (bool, error)
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

func (r *rbac) GetAllPolicies(ctx context.Context) ([]*api.Policy, []*api.Subject) {

	policies := make([]*api.Policy, 0)
	subjects := make([]*api.Subject, 0)

	lines := r.e.GetPolicy()
	for _, line := range lines {
		if len(line) < 3 {
			continue
		}
		ep := &vapi.Endpoint{
			Name:   line[1],
			Method: line[2:],
			Entity: line[1],
		}
		p := &api.Policy{
			Ptype:    api.PType_POLICY,
			Sub:      line[0],
			Endpoint: ep,
		}
		policies = append(policies, p)
	}

	groups := r.e.GetGroupingPolicy()
	for _, group := range groups {
		if len(group) < 3 {
			continue
		}
		s := &api.Subject{
			Ptype: api.ParsePtype(group[0]),
			User:  group[1],
			Group: group[2],
		}
		subjects = append(subjects, s)
	}

	return policies, subjects
}

func (r *rbac) GetPolicies(ctx context.Context, sub string) []*api.Policy {

	policies := make([]*api.Policy, 0)

	lines := r.e.GetFilteredPolicy(0, sub)
	for _, line := range lines {
		if len(line) < 3 {
			continue
		}
		ep := &vapi.Endpoint{
			Name:   line[1],
			Method: line[2:],
			Entity: line[1],
		}
		p := &api.Policy{
			Ptype:    api.PType_POLICY,
			Sub:      line[0],
			Endpoint: ep,
		}
		policies = append(policies, p)
	}

	return policies
}

func (r *rbac) AddPolicy(ctx context.Context, p *api.Policy) error {
	obj, act := parseEndpoint(p.Endpoint)

	ok, err := r.e.AddPolicy(p.Sub, obj, act)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrAlreadyExists
	}

	return nil
}

func (r *rbac) DelPolicy(ctx context.Context, p *api.Policy) error {
	obj, act := parseEndpoint(p.Endpoint)

	ok, err := r.e.RemovePolicy(p.Sub, obj, act)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrNotFound
	}

	return nil
}

func (r *rbac) GetGroupPolicies(ctx context.Context, p api.PType, sub string) []*api.Subject {
	subjects := make([]*api.Subject, 0)

	groups := r.e.GetFilteredNamedGroupingPolicy(p.Name(), 1, sub)
	for _, group := range groups {
		if len(group) < 3 {
			continue
		}
		s := &api.Subject{
			Ptype: api.ParsePtype(group[0]),
			User:  group[1],
			Group: group[2],
		}
		subjects = append(subjects, s)
	}

	return subjects
}

func (r *rbac) AddGroupPolicy(ctx context.Context, subject *api.Subject) error {

	var ptype string
	switch subject.Ptype {
	case api.PType_ROLE, api.PType_GROUP:
		ptype = subject.Ptype.Name()
	default:
		return fmt.Errorf("invalid ptype")
	}

	ok, err := r.e.AddGroupingPolicy(ptype, subject.User, subject.Group)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrAlreadyExists
	}

	return nil
}

func (r *rbac) DelGroupPolicy(ctx context.Context, subject *api.Subject) error {

	var ptype string
	switch subject.Ptype {
	case api.PType_ROLE, api.PType_GROUP:
		ptype = subject.Ptype.Name()
	default:
		return fmt.Errorf("invalid ptype")
	}

	ok, err := r.e.RemoveGroupingPolicy(ptype, subject.User, subject.Group)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	if !ok {
		return ErrNotFound
	}

	return nil
}

func (r *rbac) Enforce(ctx context.Context, p *api.Policy) (bool, error) {

	obj, act := parseEndpoint(p.Endpoint)

	ok, err := r.e.Enforce(p.Sub, obj, act)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrCasbin, err)
	}

	return ok, nil
}
