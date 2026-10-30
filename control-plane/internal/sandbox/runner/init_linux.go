//go:build linux

package runner

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// initBoot runs the minimal PID-1 responsibilities when the runner is the init of a Firecracker microVM: mount
// the pseudo-filesystems the runtimes expect, bring loopback up (the only network, used for the sinks), and open
// the second virtio drive (/dev/vdb) which the worker filled with the RunnerInput line + artifact bytes. The
// returned reader is that drive. Keep this path small on purpose.
func initBoot(logf func(string, ...any)) (io.Reader, error) {
	mounts := []struct {
		source, target, fstype string
		flags                  uintptr
	}{
		{"proc", "/proc", "proc", 0},
		{"sysfs", "/sys", "sysfs", 0},
		{"devtmpfs", "/dev", "devtmpfs", 0},
		{"tmpfs", "/tmp", "tmpfs", 0},
		{"tmpfs", "/run", "tmpfs", 0},
		{"tmpfs", "/work", "tmpfs", 0},
	}
	for _, m := range mounts {
		_ = os.MkdirAll(m.target, 0o755)
		if err := unix.Mount(m.source, m.target, m.fstype, m.flags, ""); err != nil {
			logf("mount %s on %s: %v (continuing)", m.fstype, m.target, err)
		}
	}
	if err := bringUpLoopback(); err != nil {
		logf("loopback: %v (continuing)", err)
	}
	f, err := os.Open("/dev/vdb")
	if err != nil {
		return nil, err
	}
	return f, nil
}

// bringUpLoopback assigns 127.0.0.1/8 to lo and marks it UP so the sinks and resolver are reachable.
func bringUpLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifreq, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	ifreq.SetInet4Addr([]byte{127, 0, 0, 1})
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifreq); err != nil {
		return err
	}
	mask, _ := unix.NewIfreq("lo")
	mask.SetInet4Addr([]byte{255, 0, 0, 0})
	_ = unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, mask)

	flags, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, flags); err != nil {
		return err
	}
	flags.SetUint16(flags.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, flags)
}

// powerOff halts the microVM. As PID 1 the runner must never return to the kernel, or it panics; after the report
// is written we power the VM off so the worker's Firecracker process exits.
func powerOff(logf func(string, ...any)) {
	unix.Sync()
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		logf("power off: %v", err)
		// Last resort so PID 1 does not return.
		for {
			unix.Pause()
		}
	}
}
