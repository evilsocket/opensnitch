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
	Tickers  []*time.Ticker
	Ticker   *time.Ticker
	TickChan chan time.Time
	ticky    chan time.Time
	Config   Config
}

func New(ctx context.Context, cancel context.CancelFunc, config Config) *Scheduler {
	sched := &Scheduler{
		Ctx:      ctx,
		Cancel:   cancel,
		TickChan: make(chan time.Time),
		ticky:    make(chan time.Time),
		Config:   config,
	}

	return sched
}

func NewDailyTicker(tm string) (*time.Ticker, time.Duration) {
	tms, err := time.Parse("15:04:05", tm)
	if err != nil {
		tms, err = time.Parse("15:04", tm)
		if err != nil {
			return nil, time.Millisecond
		}
	}
	wait := time.Millisecond
	now := time.Now()
	tmd := time.Date(
		now.Year(), now.Month(), now.Day(),
		tms.Hour(), tms.Minute(), tms.Second(), 0,
		now.Location(),
	)
	// if the Ticker is created before the time, wait until the ticker
	if tmd.Before(now) {
		wait = (24 * time.Hour) - now.Sub(tmd)
	} else if tmd.After(now) {
		wait = time.Until(tmd)
	}
	log.Debug("[tasks-scheduler] NewDailyTicker scheduled, waiting to start: %s", wait)

	return time.NewTicker(wait), wait
}

func (s *Scheduler) SetupDailyTimers() {
	var wg sync.WaitGroup
	for id, t := range s.Config.Time {
		wg.Add(1)
		go func() {
			defer wg.Done()

			tck, wait := NewDailyTicker(t)
			defer tck.Stop()

			go func() {
				for {
					select {
					case <-s.Ctx.Done():
						goto Exit
					case now := <-tck.C:
						for _, wd := range s.Config.Weekday {
							if wd == int(now.Weekday()) {
								s.TickChan <- now
							}
						}
					}
				}
			Exit:
				log.Debug("[tasks-scheduler] scheduler timer %d stopped", id)
			}()

			if wait > time.Millisecond {
				time.Sleep(wait)
				tck.Reset(24 * time.Hour)
			}
			s.Tickers = append(s.Tickers, tck)
		}()
	}
	wg.Wait()
}

func (s *Scheduler) Start() {
	if len(s.Tickers) > 0 {
		for _, t := range s.Tickers {
			if t != nil {
				t.Stop()
			}
		}
		if s.Cancel != nil {
			s.Cancel()
		}
	}
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
		for _, t := range s.Tickers {
			if t != nil {
				t.Stop()
			}
		}
	}
	if s.Ticker != nil {
		s.Ticker.Stop()
	}
	if s.Cancel != nil {
		s.Cancel()
	}
}

func (s *Scheduler) Tick() <-chan time.Time {
	return s.TickChan
}
