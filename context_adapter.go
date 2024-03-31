// this implementation refers to the following link:
// https://github.com/casbin/gorm-adapter/blob/master/context_adapter.go

package casbinbunadapter

import (
	"context"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

var (
	// check if the ctxBunAdapter implements the ContextAdapter interface
	_ persist.ContextAdapter = (*ctxBunAdapter)(nil) // Ensure ctxBunAdapter
)

type ctxBunAdapter struct {
	*bunAdapter
}

func NewCtxAdapter(driverName string, dataSourceName string, opts ...adapterOption) (*ctxBunAdapter, error) {
	adapter, err := NewAdapter(driverName, dataSourceName, opts...)
	if err != nil {
		return nil, err
	}
	return &ctxBunAdapter{adapter}, nil
}

// executeWithContext is a helper function to execute a function with context and return the result or error.
func executeWithContext(ctx context.Context, fn func() error) error {
	done := make(chan error)
	go func() {
		done <- fn()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// LoadPolicyCtx loads all policy rules from the storage with context.
func (a *ctxBunAdapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	return executeWithContext(ctx, func() error {
		return a.LoadPolicy(model)
	})
}

// SavePolicyCtx saves all policy rules to the storage with context.
func (a *ctxBunAdapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	return executeWithContext(ctx, func() error {
		return a.SavePolicy(model)
	})
}

// AddPolicyCtx adds a policy rule to the storage with context.
// This is part of the Auto-Save feature.
func (a *ctxBunAdapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return executeWithContext(ctx, func() error {
		return a.AddPolicy(sec, ptype, rule)
	})
}

// RemovePolicyCtx removes a policy rule from the storage with context.
// This is part of the Auto-Save feature.
func (a *ctxBunAdapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return executeWithContext(ctx, func() error {
		return a.RemovePolicy(sec, ptype, rule)
	})
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage with context.
// This is part of the Auto-Save feature.
func (a *ctxBunAdapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return executeWithContext(ctx, func() error {
		return a.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	})
}
