package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

// if the computer enters sleep mode, the duration of the sleep is substracted to time.Sleep()
// Example:
// - the timer fires at 18:51; it'll be checked again in 1h and will fire in 24h.
// - last check at 00:51
// - computer put to sleep at 01:51
// - it wakes up at 10:31, having slept for 8h.
// - the timer attempts to fire at 10:31, exactly 8h before the deadline.
func timeHasDrifted(now, tms *time.Time) bool {
	return now.Minute() != tms.Minute() && now.Second() != tms.Second()
}

func waitToStart(ctx context.Context, id int, t string, wait time.Duration, tms *time.Time, drifted chan struct{}) (bool, bool) {
	now := time.Now()
	for {
		select {
		case <-ctx.Done():
			goto Exit
		case <-time.After(wait):
			realNow := time.Now()
			log.Debug("[tasks-scheduler] %d, %s ticker ready: %s - after: %s", id, t, realNow.Format(time.DateTime), now.Format(time.DateTime))
			goto Continue
		case <-drifted:
			//stopTimer(tck)
			goto Reschedule
		}
	}
Exit:
	return true, false
Continue:
	return false, false
Reschedule:
	return false, true
}

// calcDailyTicker calculates the amount of time to wait until the timer must start.
func calcDailyTicker(tm string) (*time.Time, time.Duration) {
	// support 2 formats when specifying times:
	// - 15:04:05
	// - 15:04 -> assume seconds == 00
	tms, err := time.Parse("15:04:05", tm)
	if err != nil {
		tms, err = time.Parse("15:04", tm)
		if err != nil {
			log.Error("[tasks-scheduler] invalid daily ticker time: %s", err)
			return nil, time.Millisecond
		}
	}
	wait := time.Millisecond
	now := time.Now().Round(0)
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
	log.Debug("[tasks-scheduler] NewDailyTicker scheduled %s, waiting to start: %s", tm, wait)

	return &tmd, wait
}

// NewDailyTicker creates a new ticker.
func NewDailyTicker(tm string) (*time.Ticker, *time.Time, time.Duration) {
	tms, wait := calcDailyTicker(tm)
	return time.NewTicker(wait), tms, wait
}

func (s *Scheduler) stopTimer(id int, t *time.Ticker) {
	t.Stop()
	s.mu.Lock()
	delete(s.Tickers, id)
	s.mu.Unlock()
}

// Instruct the timers to stop.
// Mainly when the clock has drifted.
func (s *Scheduler) restartTimers(drifted chan struct{}) {
	timers := len(s.Config.Time)
	for range timers {
		select {
		case drifted <- struct{}{}:
		default:
			log.Trace("[tasks-scheduler] restartTimers() unable to deliver")
		}
	}
}

// SetupDailyTimers creates the daily timers that will fire every 24h at the configured hour.
// We create the timers and wait for the remaining time from now until the configured hour.
// From that on, the timer will be scheduled to tick every 24h.
func (s *Scheduler) SetupDailyTimers() {
	var wg sync.WaitGroup
	drifted := make(chan struct{})

	for id, t := range s.Config.Time {
		wg.Add(1)
		go func(drifted chan struct{}) {
			defer wg.Done()

		Reschedule:
			tck, tms, wait := NewDailyTicker(t)
			if tck == nil {
				log.Error("[tasks-scheduler] invalid timer %d-%s", id, t)
				return
			}
			// save tickers to stop them later when stopping the scheduler.
			s.mu.Lock()
			s.Tickers[id] = tck
			s.mu.Unlock()

			exit, resched := waitToStart(s.Ctx, id, t, wait, tms, drifted)
			if exit {
				goto Exit
			}
			if resched {
				s.stopTimer(id, tck)
				goto Reschedule
			}

			log.Debug("[tasks-scheduler] %d, %s daily ticker started", id, t)
			for {
				select {
				case <-s.Ctx.Done():
					goto Exit
				case <-drifted:
					now := time.Now()
					log.Debug("[tasks-scheduler] %d, %s running ticker drifted, now: %v", id, t, now.Format(time.DateTime))
					s.stopTimer(id, tck)
					goto Reschedule
				case now := <-tck.C:
					realNow := time.Now()
					//log.Debug("[tasks-scheduler] %d, %s tick now: %s real-now: %s tms: %s", id, t, now.Format(time.DateTime), realNow.Format(time.DateTime), tms.Format(time.DateTime))
					// these timers are scheduled every hour, so the minute and second should match.
					// If they don't, the clock has drifted.
					if timeHasDrifted(&realNow, tms) {
						log.Debug("[tasks-scheduler] %d, %s tick out-of-sync, rescheduling: %s", id, t, realNow.Format(time.DateTime))
						s.restartTimers(drifted)
						s.stopTimer(id, tck)
						goto Reschedule
					}

					today := int(now.Weekday())
					for _, wd := range s.Config.Weekday {
						if wd != today {
							continue
						}
						//log.Debug("[tasks-scheduler] %d, %s tick is today %d", id, t, c)
						if realNow.Hour() == tms.Hour() {
							log.Debug("[tasks-scheduler] %d, %s ticker fired", id, t)
							s.TickChan <- now
							tck.Reset(1 * time.Hour)
						}
					}
				}
			}

		Exit:
			// wait for ticks while the tickers are active.
			// stop the ticker only when stopping the scheduler.
			tck.Stop()
			log.Debug("[tasks-scheduler] scheduler timer %d stopped", id)
		}(drifted)
	}
	wg.Wait()

	log.Debug("[tasks-scheduler] SetupDailyTimers() finished")
}
