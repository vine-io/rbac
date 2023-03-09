package api

import (
	"strings"

	"github.com/vine-io/vine/lib/api"
)

func (m PType) Name() string {
	switch m {
	case PType_POLICY:
		return "p"
	case PType_ROLE:
		return "g"
	case PType_GROUP:
		return "g2"
	default:
		return "p"
	}
}

func ParsePtype(text string) PType {
	switch text {
	case "p":
		return PType_POLICY
	case "g":
		return PType_ROLE
	case "g2":
		return PType_GROUP
	default:
		return PType_UNKNOWN
	}
}

func NewPolicy(sub string, endpoint *api.Endpoint) *Policy {
	return &Policy{
		Ptype:    PType_POLICY,
		Sub:      sub,
		Endpoint: endpoint,
	}
}

func NewPolicyWithString(sub, obj, act string) *Policy {
	ep := &api.Endpoint{Name: obj, Method: []string{act}}
	ep.Name = obj
	if !strings.Contains(obj, ".") {
		ep.Entity = obj
	}

	return &Policy{
		Ptype:    PType_POLICY,
		Sub:      sub,
		Endpoint: ep,
	}
}

func (m Policy) ToCasbinPolicy() (sub string, obj string, act string) {
	sub = "p"
	if m.Endpoint != nil {

		if m.Endpoint.Entity != "" {
			obj = m.Endpoint.Entity
		} else {
			obj = m.Endpoint.Name
		}

		if len(m.Endpoint.Method) > 0 {
			act = m.Endpoint.Method[0]
		}
	}
	return
}
