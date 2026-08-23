package workers

import (
	"context"
	"errors"
	"sync"
)

type Job func(context.Context) error
type Pool struct {
	jobs   chan Job
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

func New(size, queueSize int) *Pool {
	if size < 1 {
		size = 1
	}
	if queueSize < size {
		queueSize = size
	}
	return &Pool{jobs: make(chan Job, queueSize)}
}
func (p *Pool) Start(parent context.Context, size int) {
	ctx, cancel := context.WithCancel(parent)
	p.cancel = cancel
	for i := 0; i < size; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-p.jobs:
					if job != nil {
						_ = job(ctx)
					}
				}
			}
		}()
	}
}
func (p *Pool) Submit(job Job) error {
	select {
	case p.jobs <- job:
		return nil
	default:
		return errors.New("worker queue is full")
	}
}
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}
