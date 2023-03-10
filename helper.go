package rbac

import (
	"fmt"
	"strings"

	"github.com/vine-io/vine/lib/api"
)

var (
	DefaultAdminName = "admin"

	DefaultModel = fmt.Sprintf(`### rbac model
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && g2(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "administrator" || r.sub == "root" || r.sub == "%s"`, DefaultAdminName)
)

var (
	ErrAlreadyExists = fmt.Errorf("policy already exists")
	ErrNotFound      = fmt.Errorf("policy not found")
	ErrCasbin        = fmt.Errorf("casbin error")
)

func parseEndpoint(endpoint *api.Endpoint) (obj string, act string) {
	if endpoint.Entity != "" {
		obj = endpoint.Entity
	}
	if obj == "" {
		obj = endpoint.Name
	}

	act = strings.Join(endpoint.Method, ",")
	return
}
