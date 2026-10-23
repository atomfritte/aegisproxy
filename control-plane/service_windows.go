//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const windowsServiceName = "AegisControlPlane"

type windowsService struct {
	run  func(ctx context.Context) error
	err  error
	elog *eventlog.Log
}

// reportFailure writes a fatal error to the Application event log: under the SCM there is no console,
// and configuration errors occur before AEGIS_LOG_FILE is open. The installer registers the source.
func (w *windowsService) reportFailure(err error) {
	slog.Error("control-plane terminated", "error", err)
	if w.elog != nil {
		_ = w.elog.Error(1, fmt.Sprintf("AegisProxy control-plane terminated: %v", err))
	}
}

// Execute implements svc.Handler: it runs the control-plane until the SCM sends Stop/Shutdown.
func (w *windowsService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			w.err = err
			if err != nil {
				w.reportFailure(err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if w.err = <-done; w.err != nil {
					w.reportFailure(w.err)
				}
				return false, 0
			}
		}
	}
}

// runAsWindowsService runs under the Windows Service Control Manager. With force (the "service"
// argument the installer puts into the ImagePath) the dispatcher is always used; otherwise the process
// is detected as a service by its parent (services.exe in session 0, kept for older installations).
func runAsWindowsService(run func(ctx context.Context) error, force bool) (bool, error) {
	if !force {
		isService, err := svc.IsWindowsService()
		if err != nil || !isService {
			return false, nil
		}
	}
	h := &windowsService{run: run}
	if elog, err := eventlog.Open(windowsServiceName); err == nil {
		h.elog = elog
		defer elog.Close()
	}
	if err := svc.Run(windowsServiceName, h); err != nil {
		if h.elog != nil {
			_ = h.elog.Error(2, fmt.Sprintf("AegisProxy control-plane: service dispatcher failed: %v", err))
		}
		return true, err
	}
	return true, h.err
}
