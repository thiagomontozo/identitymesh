package workers

import (
	"context"
	"testing"
	"time"
)

func TestBoundedPool(t *testing.T) {
	p := New(1, 1)
	block := make(chan struct{})
	if err := p.Submit(func(context.Context) error { <-block; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.Submit(func(context.Context) error { return nil }); err == nil {
		t.Fatal("bounded queue must reject overflow")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx, 1)
	close(block)
	time.Sleep(10 * time.Millisecond)
	cancel()
	p.Stop()
}
