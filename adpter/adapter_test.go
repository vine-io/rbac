package adpter

import (
	"log"
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
	"github.com/stretchr/testify/assert"
	clientv3 "go.etcd.io/etcd/client/v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const dsn = "test.sqlite.db"

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func testGetPolicyWithoutOrder(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	if !arrayEqualsWithoutOrder(myRes, res) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func arrayEqualsWithoutOrder(a [][]string, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[int]string)
	mapB := make(map[int]string)
	order := make(map[int]struct{})
	l := len(a)

	for i := 0; i < l; i++ {
		mapA[i] = util.ArrayToString(a[i])
		mapB[i] = util.ArrayToString(b[i])
	}

	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			if _, ok := order[j]; ok {
				if j == l-1 {
					return false
				} else {
					continue
				}
			}
			if mapA[i] == mapB[j] {
				order[j] = struct{}{}
				break
			} else if j == l-1 {
				return false
			}
		}
	}
	return true
}

func initPolicy(t *testing.T, a persist.Adapter) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, err := casbin.NewEnforcer("../examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err = a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testSaveLoad(t *testing.T, a persist.Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func initAdapterWithGormInstance(t *testing.T, db *gorm.DB) *GormAdapter {
	// Create an adapter
	a, _ := NewGormAdapter(db)
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func initAdapterWithEtcdInstance(t *testing.T, conn *clientv3.Client) *EtcdAdapter {
	// Create an adapter
	a, _ := NewEtcdAdapter(conn)
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func testAutoSave(t *testing.T, a persist.Adapter) {

	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)
	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testFilteredPolicy(t *testing.T, a persist.Adapter) {
	// NewEnforcer() without an adapter will not auto load the policy
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf")
	// Now set the adapter
	e.SetAdapter(a)

	// Load only alice's policies
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"alice"}}))
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	// Load only bob's policies
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"bob"}}))
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Load policies for data2_admin
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"data2_admin"}}))
	testGetPolicy(t, e, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Load policies for alice and bob
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"alice", "bob"}}))
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})

	assert.Nil(t, e.LoadFilteredPolicy(BatchFilter{
		filters: []Filter{
			{V0: []string{"alice"}},
			{V1: []string{"data2"}},
		},
	}))
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
}

func testUpdatePolicy(t *testing.T, a persist.Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "write"})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdatePolicies(t *testing.T, a persist.Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdatePolicies([][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}}, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "read"}})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "read"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdateFilteredPolicies(t *testing.T, a *GormAdapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdateFilteredPolicies([][]string{{"alice", "data1", "write"}}, 0, "alice", "data1", "read")
	e.UpdateFilteredPolicies([][]string{{"bob", "data2", "read"}}, 0, "bob", "data2", "write")
	e.LoadPolicy()
	testGetPolicyWithoutOrder(t, e, [][]string{{"alice", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data2", "read"}})
}

func TestAdapters(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	defer os.Remove(dsn)

	a := initAdapterWithGormInstance(t, db)

	testSaveLoad(t, a)
	testAutoSave(t, a)
}

func TestEtcdAdapters(t *testing.T) {
	conn, err := clientv3.New(clientv3.Config{
		Endpoints: []string{"127.0.0.1:2379"},
	})

	if err != nil {
		panic(err)
	}

	a := initAdapterWithEtcdInstance(t, conn)

	testSaveLoad(t, a)
	//testAutoSave(t, a)
}

func TestPolicy(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a := initAdapterWithGormInstance(t, db)

	testFilteredPolicy(t, a)
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)
}

func TestAddPolicies(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a := initAdapterWithGormInstance(t, db)
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)
	e.AddPolicies([][]string{{"jack", "data1", "read"}, {"jack2", "data1", "read"}})
	e.LoadPolicy()

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"jack", "data1", "read"}, {"jack2", "data1", "read"}})

	_, err = e.Enforce("administrator", "ss", "ss")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := e.Enforce("lack", "ss", "read")
	if ok {
		t.Fatal("lack not allow", ok)
	}

	_, err = e.AddGroupingPolicy("lack", "administrator")
	if err != nil {
		t.Fatal(err)
	}
	e.LoadPolicy()

	t.Log(e.GetPolicy())
	t.Log(e.GetRolesForUser("lack"))

	ok, err = e.Enforce("administrator", "ss", "read")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ok)
}

func TestEtcdAddPolicies(t *testing.T) {
	conn, err := clientv3.New(clientv3.Config{
		Endpoints: []string{"127.0.0.1:2379"},
	})

	if err != nil {
		panic(err)
	}

	a := initAdapterWithEtcdInstance(t, conn)

	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)
	e.AddPolicies([][]string{{"jack", "data1", "read"}, {"jack2", "data1", "read"}})
	e.LoadPolicy()

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"jack", "data1", "read"}, {"jack2", "data1", "read"}})

	_, err = e.Enforce("administrator", "ss", "ss")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := e.Enforce("lack", "ss", "read")
	if ok {
		t.Fatal("lack not allow", ok)
	}

	_, err = e.AddGroupingPolicy("lack", "administrator")
	if err != nil {
		t.Fatal(err)
	}
	e.LoadPolicy()

	t.Log(e.GetPolicy())
	t.Log(e.GetRolesForUser("lack"))

	ok, err = e.Enforce("administrator", "ss", "read")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ok)
}

func TestTransaction(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a := initAdapterWithGormInstance(t, db)
	e, _ := casbin.NewEnforcer("../examples/rbac_model.conf", a)
	err = e.GetAdapter().(*GormAdapter).Transaction(e, func(e casbin.IEnforcer) error {
		_, err := e.AddPolicy("jack", "data1", "write")
		if err != nil {
			return err
		}
		_, err = e.AddPolicy("jack", "data2", "write")
		//err = errors.New("some error")
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return
	}
}
