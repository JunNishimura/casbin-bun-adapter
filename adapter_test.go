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
