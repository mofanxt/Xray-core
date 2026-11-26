package outbound

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type removalProxy struct {
	started int
	closed  int
}

func TestSelectCacheKeepsSelectorBoundariesAndOwnsResults(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"a-only", "a,b-node", "b-only"} {
		if err := manager.AddHandler(ctx, &Handler{tag: tag}); err != nil {
			t.Fatal(err)
		}
	}
	wantCombined := []string{"a,b-node"}
	wantSeparate := []string{"a,b-node", "a-only", "b-only"}
	combined := manager.Select([]string{"a,b"})
	separate := manager.Select([]string{"a", "b"})
	if !slices.Equal(combined, wantCombined) || !slices.Equal(separate, wantSeparate) {
		t.Fatalf("combined=%v separate=%v", combined, separate)
	}
	combined[0] = "changed by caller"
	cached := manager.Select([]string{"a,b"})
	cached[0] = "cache hit changed by caller"
	if got := manager.Select([]string{"a,b"}); !slices.Equal(got, wantCombined) {
		t.Fatalf("cached selector returned %v, want %v", got, wantCombined)
	}
	if err := manager.RemoveHandler(ctx, "a,b-node"); err != nil {
		t.Fatal(err)
	}
	if got := manager.Select([]string{"a,b"}); len(got) != 0 {
		t.Fatalf("removed tag returned from cache: %v", got)
	}
}

func (*removalProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
	return nil
}

func (p *removalProxy) Start() error {
	p.started++
	return nil
}

func (p *removalProxy) Close() error {
	p.closed++
	return nil
}

type managedRemovalProxy struct {
	removalProxy
	outboundStarts int
	outboundErr    error
	stopped        int
}

func (p *managedRemovalProxy) StartOutbound() error {
	p.outboundStarts++
	return p.outboundErr
}

func (p *managedRemovalProxy) StopOutbound() error {
	p.stopped++
	return nil
}

func TestOutboundRemovalOnlyStopsOptInRuntime(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	plain := &removalProxy{}
	runtime := &managedRemovalProxy{}
	for _, handler := range []*Handler{
		{tag: "plain", proxy: plain},
		{tag: "runtime", proxy: runtime},
	} {
		if err := manager.AddHandler(ctx, handler); err != nil {
			t.Fatal(err)
		}
		if err := manager.RemoveHandler(ctx, handler.tag); err != nil {
			t.Fatal(err)
		}
		if manager.GetHandler(handler.tag) != nil {
			t.Fatalf("handler %s remained registered", handler.tag)
		}
	}
	if plain.started != 0 || runtime.started != 0 || plain.closed != 0 || runtime.closed != 0 {
		t.Fatalf("ordinary lifecycle invoked: plain=%+v, managed=%+v", plain, runtime.removalProxy)
	}
	if runtime.outboundStarts != 1 || runtime.stopped != 1 {
		t.Fatalf("managed runtime started=%d, stopped=%d", runtime.outboundStarts, runtime.stopped)
	}
}

func TestOutboundStartupRollsBackActiveRuntimes(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	plain := &removalProxy{}
	started := &managedRemovalProxy{}
	failed := &managedRemovalProxy{outboundErr: errors.New("startup error")}
	for _, handler := range []*Handler{
		{proxy: plain}, {proxy: started}, {proxy: failed},
	} {
		if err := manager.AddHandler(ctx, handler); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Start(); err == nil {
		t.Fatal("expected manager.Start to fail")
	}
	if plain.started != 0 || plain.closed != 0 || started.closed != 0 ||
		started.outboundStarts != 1 || started.stopped != 1 || failed.stopped != 0 {
		t.Fatalf("invalid rollback: plain=%+v, started=%+v, failed=%+v", plain, started, failed)
	}
}
