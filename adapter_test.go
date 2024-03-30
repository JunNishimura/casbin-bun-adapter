package casbinbunadapter

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, want [][]string) {
	got := e.GetPolicy()

	if !util.Array2DEquals(want, got) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func initPolicy(t *testing.T, adapter *bunAdapter) {
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	if err != nil {
		panic(err)
	}

	if err := adapter.SavePolicy(e.GetModel()); err != nil {
		panic(err)
	}

	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	if err := adapter.LoadPolicy(e.GetModel()); err != nil {
		panic(err)
	}
	testGetPolicy(
		t,
		e,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
	)
}

func initAdapter(t *testing.T, driverName, dataSourceName string, opts ...adapterOption) *bunAdapter {
	a, err := NewAdapter(driverName, dataSourceName, opts...)
	if err != nil {
		panic(err)
	}

	initPolicy(t, a)

	return a
}

func TestBunAdapter_AddPolicy(t *testing.T) {
	a := initAdapter(t, "mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	if _, err := e.AddPolicy("jack", "data1", "read"); err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	testGetPolicy(
		t,
		e,
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"jack", "data1", "read"}},
	)
}

func TestBunAdapter_AddPolicies(t *testing.T) {
	a := initAdapter(t, "mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	if _, err := e.AddPolicies([][]string{{"jack", "data1", "read"}, {"jill", "data2", "write"}}); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	testGetPolicy(
		t,
		e,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"jack", "data1", "read"},
			{"jill", "data2", "write"},
		},
	)
}

func TestBunAdapter_RemovePolicy(t *testing.T) {
	a := initAdapter(t, "mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	if _, err := e.RemovePolicy("alice", "data1", "read"); err != nil {
		t.Fatalf("failed to remove policy: %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	testGetPolicy(
		t,
		e,
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
	)
}

func TestBunAdapter_RemovePolicies(t *testing.T) {
	a := initAdapter(t, "mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	if _, err := e.RemovePolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}); err != nil {
		t.Fatalf("failed to remove policies: %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	testGetPolicy(
		t,
		e,
		[][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
	)
}

func TestBunAdapter_RemoveFilteredPolicy(t *testing.T) {
	a := initAdapter(t, "mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	// 1. check if the policy with alice is all removed
	if _, err := e.AddPolicy("alice", "data1", "write"); err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data1", "write"},
		},
	)
	if _, err := e.RemoveFilteredPolicy(0, "alice"); err != nil {
		t.Fatalf("failed to remove filtered policy: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)
	// 2. check if the policy with data1 is all removed
	if _, err := e.AddPolicies([][]string{{"alice", "data1", "read"}, {"alice", "data1", "write"}, {"alice", "data2", "read"}, {"alice", "data2", "write"}}); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data1", "read"},
			{"alice", "data1", "write"},
			{"alice", "data2", "read"},
			{"alice", "data2", "write"},
		},
	)
	if _, err := e.RemoveFilteredPolicy(1, "data1"); err != nil {
		t.Fatalf("failed to remove filtered policy: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data2", "read"},
			{"alice", "data2", "write"},
		},
	)
	// 3. check if the policy with alice and data2 is all removed
	if _, err := e.RemoveFilteredPolicy(0, "alice", "data2"); err != nil {
		t.Fatalf("failed to remove filtered policy: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)
	// 4. check if the all policies are removed when fieldValues is empty
	if _, err := e.RemoveFilteredPolicy(0, ""); err != nil {
		t.Fatalf("failed to remove filtered policy: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(t, e, [][]string{})
}
