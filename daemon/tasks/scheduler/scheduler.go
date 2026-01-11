// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

type Config struct {
	Time    []string `json:"time"`
	Weekday []int    `json:"weekday"`
	Hour    []int    `json:"hour"`
	Minute  []int    `json:"minute"`
	Second  []int    `json:"second"`
	Repeat  bool     `json:"repeat"`
}

// Scheduler is a general purpose tasks scheduler, to run jobs at
// regular intervals, pretty much like cron, with different syntax.
// Configuration example:
// "schedule": [
//     {
//         "description": "run this task on Satuday and Sunday, at 9am and 23pm",
//         "weekday": [5,6],
//         "time": ["09:00:00", "23:00:00"]
//     },
//     {
//         "description": "also run this task on Fridays every 30m",
//         "weekday": [4],
//         "minute": [30]
//     }
// ],
type Scheduler struct {
	Ctx      context.Context
	Cancel   context.CancelFunc
	Tickers  map[int]*time.Ticker
	Ticker   *time.Ticker
	TickChan chan time.Time
	ticky    chan time.Time
	Config   Config

	mu *sync.RWMutex
}

func New(ctx context.Context, cancel context.CancelFunc, config Config) *Scheduler {
	sched := &Scheduler{
		Ctx:      ctx,
		Cancel:   cancel,
		TickChan: make(chan time.Time),
		ticky:    make(chan time.Time),
		Tickers:  make(map[int]*time.Ticker),
		Config:   config,
		mu:       &sync.RWMutex{},
	}

	return sched
}

func (s *Scheduler) Start() {
	log.Debug("[tasks-scheduler] Start()")

	if len(s.Config.Time) > 0 {
		go s.SetupDailyTimers()
	}
	go func() {
		hourMatched := false
		minMatched := false
		secMatched := false

		hasHours := len(s.Config.Hour) > 0
		hasMins := len(s.Config.Minute) > 0
		hasSeconds := len(s.Config.Second) > 0
		resolution := time.Second
		// if there're no seconds specified, and minutes are specified,
		// minimum timer resolution is every minute
		if hasMins && !hasSeconds {
			resolution = time.Minute
		} else if hasHours && !hasMins && !hasSeconds {
			resolution = time.Hour
		}
		log.Trace("[tasks-scheduler] resolution: %v\n", resolution)
		s.Ticker = time.NewTicker(resolution)
		defer s.Ticker.Stop()

		sch := s.Config
		for {
			select {
			case <-s.Ctx.Done():
				goto Exit
			case now := <-s.Ticker.C:
				isWeekday := false

				for _, wd := range sch.Weekday {
					if wd == int(now.Weekday()) {
						isWeekday = true
					}
				}
				if !isWeekday {
					goto Continue
				}
				if hasHours {
					for _, mm := range sch.Hour {
						if mm == now.Hour() {
							hourMatched = true
							break
						}
					}
				}
				if hasMins {
					for _, mm := range sch.Minute {
						if mm == now.Minute() {
							minMatched = true
							break
						}
					}
				}
				if hasSeconds {
					for _, ss := range sch.Second {
						if ss == now.Second() {
							secMatched = true
						}
					}
				}

				if // match only hours
				(hasHours && !hasMins && !hasSeconds && hourMatched) ||
					// only minutes
					(!hasHours && hasMins && !hasSeconds && minMatched) ||
					// only seconds
					(!hasHours && !hasMins && hasSeconds && secMatched) ||
					// mins + secs matched
					(!hasHours && hasMins && hasSeconds && minMatched && secMatched) ||
					(hasHours && hasMins && hasSeconds && hourMatched && minMatched && secMatched) {
					s.TickChan <- time.Now()
					log.Trace("[tasks-scheduler] scheduling new job, hour: %d, min: %d, sec: %d, hours: %v mins: %v, secs: %v\n", now.Hour(), now.Minute(), now.Second(), hourMatched, minMatched, secMatched)
				}
			}
		Continue:
			hourMatched = false
			minMatched = false
			secMatched = false
		}
	Exit:
		log.Info("[tasks-scheduler] stopped")
	}()

}

func (s *Scheduler) Stop() {
	if len(s.Tickers) > 0 {
		for id, t := range s.Tickers {
			if t != nil {
				t.Stop()
			}
			t = nil
			delete(s.Tickers, id)
		}
		s.Tickers = make(map[int]*time.Ticker)
	}
	if s.Ticker != nil {
		s.Ticker.Stop()
	}
}

func (s *Scheduler) Tick() <-chan time.Time {
	return s.TickChan
}
