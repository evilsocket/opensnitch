package tasks

// Copyright 2024 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

/*
Package tasks manages actions launched by/to the daemon.

These tasks are handled by the TaskManager, which is in charge of start new
task, update and stop them.

The name of each task serves as the unique key inside the task manager.
Some tasks will be unique, like SocketsMonitor, and others might have more than one instance, like "pid-monitor-123", "pid-monitor-987".

Tasks run in background.

Some tasks may run periodically (every 5s, every 2 days, ...), others will run until stop and others until a timeout.

*/
