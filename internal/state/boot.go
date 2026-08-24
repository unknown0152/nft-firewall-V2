package state

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"syscall"
)

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CurrentBootID reads the kernel boot epoch without consulting environment or
// network state. Tests may supply a GenerationMetadata BootID explicitly.
func CurrentBootID() (string, error) {
	path := "/proc/sys/kernel/random/boot_id"
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	data := make([]byte, 128)
	n, readErr := f.Read(data)
	closeErr := f.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	value := strings.TrimSpace(string(data[:n]))
	if !bootIDPattern.MatchString(value) {
		return "", errors.New("kernel boot id is malformed")
	}
	return value, nil
}
