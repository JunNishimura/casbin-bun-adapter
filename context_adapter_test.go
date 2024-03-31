package casbinbunadapter

import (
	"context"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
)

func mockExecuteWithContextTimeOut(ctx context.Context, fn func() error) error {
	done := make(chan error)
	go func() {
		time.Sleep(500 * time.Microsecond)
		done <- fn()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func clearDBPolicy() (*casbin.Enforcer, *ctxBunAdapter) {
	ca, err := NewCtxAdapter("mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	if err != nil {
		panic(err)
	}
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", ca)
	if err != nil {
		panic(err)
	}
	e.ClearPolicy()
	_ = e.SavePolicy()

	return e, ca
}

func TestCtxBunAdapter_LoadPolicyCtx(t *testing.T) {
	e, _ := casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	ca, err := NewCtxAdapter("mysql", "root:root@tcp(127.0.0.1:3306)/test", WithDebugMode())
	if err != nil {
		panic(err)
	}
	_ = ca.SavePolicyCtx(context.Background(), e.GetModel())
	assert.NoError(t, ca.LoadPolicyCtx(context.Background(), e.GetModel()))
	e, _ = casbin.NewEnforcer("testdata/rbac_model.conf", ca)
	testGetPolicy(
		t,
		e,
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
	)

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.LoadPolicyCtx(ctx, e.GetModel()), "context deadline exceeded")
}

func TestCtxBunAdapter_SavePolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	e.EnableAutoSave(false)
	_, _ = e.AddPolicy("alice", "data1", "read")
	assert.NoError(t, ca.SavePolicyCtx(context.Background(), e.GetModel()))
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"alice", "data1", "read"},
		},
	)

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.SavePolicyCtx(ctx, e.GetModel()), "context deadline exceeded")
}

func TestCtxBunAdapter_AddPolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	if err := ca.AddPolicyCtx(context.Background(), "p", "p", []string{"alice", "data1", "read"}); err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"alice", "data1", "read"},
		},
	)

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.AddPolicyCtx(ctx, "p", "p", []string{"alice", "data2", "read"}), "context deadline exceeded")
}

func TestCtxBunAdapter_RemovePolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	_ = ca.AddPolicyCtx(context.Background(), "p", "p", []string{"alice", "data1", "read"})
	_ = ca.AddPolicyCtx(context.Background(), "p", "p", []string{"alice", "data2", "read"})
	_ = ca.RemovePolicyCtx(context.Background(), "p", "p", []string{"alice", "data1", "read"})
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"alice", "data2", "read"},
		},
	)

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.RemovePolicyCtx(ctx, "p", "p", []string{"alice", "data2", "read"}), "context deadline exceeded")
}

func TestCtxBunAdapter_RemoveFilteredPolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	_ = ca.AddPolicyCtx(context.Background(), "p", "p", []string{"alice", "data1", "read"})
	_ = ca.AddPolicyCtx(context.Background(), "p", "p", []string{"alice", "data2", "read"})
	_ = ca.AddPolicyCtx(context.Background(), "p", "p", []string{"bob", "data1", "read"})
	_ = ca.RemoveFilteredPolicyCtx(context.Background(), "p", "p", 0, "alice")
	_ = e.LoadPolicy()
	testGetPolicy(
		t,
		e,
		[][]string{
			{"bob", "data1", "read"},
		},
	)

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.RemoveFilteredPolicyCtx(ctx, "p", "p", 0, "alice"), "context deadline exceeded")
}
