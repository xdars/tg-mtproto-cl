package debouncer

import (
	"sync"
	"time"
)

type Debouncer struct {
	m     sync.Mutex
	t     time.Duration
	timer *time.Timer
}

func Register(t time.Duration) func(f func()) {
	d := &Debouncer{t: t}
	return func(f func()) {
		d.Add(f)
	}
}

func (d *Debouncer) Add(f func()) {
	d.m.Lock()
	defer d.m.Unlock() // the end

	if d.timer != nil {
		d.timer.Stop()
	}

	d.timer = time.AfterFunc(d.t, f)
}
