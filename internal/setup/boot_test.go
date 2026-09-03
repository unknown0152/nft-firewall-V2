package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/bootguard"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
)

const (
	testKernelRelease = "6.12.0-nftfw-test"
	testBootID1       = "11111111-1111-4111-8111-111111111111"
	testBootID2       = "22222222-2222-4222-8222-222222222222"
	testBootID3       = "33333333-3333-4333-8333-333333333333"
)

type bootFixture struct {
	t              *testing.T
	paths          Paths
	base           *systemRunner
	commands       []string
	fail           string
	mutate         bool
	installed      map[string]bool
	arch           string
	release        string
	efiOutput      string
	mountOptions   string
	initramfsGuard bool
	resumeGuard    bool
}

type timedBootRunner struct {
	timeout time.Duration
}

func (r *timedBootRunner) Run(context.Context, []byte, string, ...string) ([]byte, error) {
	return nil, errors.New("ordinary runner must not be used")
}

func (r *timedBootRunner) RunWithTimeout(_ context.Context, _ []byte, timeout time.Duration, _ string, _ ...string) ([]byte, error) {
	r.timeout = timeout
	return []byte("updated\n"), nil
}

func newBootFixture(t *testing.T) *bootFixture {
	t.Helper()
	root := t.TempDir()
	paths := DefaultPaths()
	paths.GRUBSourceDir = filepath.Join(root, "etc/default/grub.d")
	paths.GRUBFragment = filepath.Join(paths.GRUBSourceDir, "90-nftfw-ipv6-disabled.cfg")
	paths.GRUBGenerated = filepath.Join(root, "boot/grub/grub.cfg")
	paths.GRUBUpdate = filepath.Join(root, "usr/sbin/update-grub")
	paths.BootKernelDir = filepath.Join(root, "boot")
	paths.ProcCmdline = filepath.Join(root, "proc/cmdline")
	paths.ProcBootID = filepath.Join(root, "proc/boot_id")
	paths.IPv6DisableParam = filepath.Join(root, "sys/ipv6-disable")
	paths.ProcIfInet6 = filepath.Join(root, "proc/if_inet6")
	paths.SystemdBootEntries = filepath.Join(root, "boot/loader/entries")
	paths.UKIDir = filepath.Join(root, "boot/EFI/Linux")
	paths.ExtlinuxDir = filepath.Join(root, "boot/extlinux")
	paths.AlternateGRUBDir = filepath.Join(root, "boot/grub2")
	paths.EFIFirmwareDir = filepath.Join(root, "sys/firmware/efi")
	paths.EFIBootManager = filepath.Join(root, "usr/bin/efibootmgr")
	paths.BootHoldMarker = filepath.Join(root, "etc/nftfw/setup-boot-hold-v1")
	paths.BootHoldReady = filepath.Join(root, "run/nftfw/setup-boot-hold-ready")
	paths.BootHoldRelease = filepath.Join(root, "run/nftfw/setup-boot-release")
	for _, directory := range []string{
		paths.GRUBSourceDir, filepath.Dir(paths.GRUBGenerated), filepath.Dir(paths.GRUBUpdate),
		filepath.Dir(paths.ProcCmdline), filepath.Dir(paths.IPv6DisableParam),
		filepath.Dir(paths.BootHoldMarker), filepath.Dir(paths.BootHoldReady),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, paths.GRUBUpdate, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	writeFixture(t, paths.EFIBootManager, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	writeFixture(t, filepath.Join(paths.BootKernelDir, "vmlinuz-"+testKernelRelease), []byte("kernel\n"), 0o644)
	writeFixture(t, paths.GRUBGenerated, initialGRUB(), 0o600)
	writeFixture(t, paths.ProcCmdline, []byte("root=/dev/test ro quiet\n"), 0o600)
	writeFixture(t, paths.ProcBootID, []byte(testBootID1+"\n"), 0o600)
	writeFixture(t, paths.IPv6DisableParam, []byte("N\n"), 0o600)
	writeFixture(t, paths.ProcIfInet6, nil, 0o600)
	return &bootFixture{
		t: t, paths: paths, base: &systemRunner{}, mutate: true, arch: "x86_64", release: testKernelRelease,
		installed: map[string]bool{"grub-pc": true}, mountOptions: "rw,relatime",
		efiOutput: "BootCurrent: 0001\nBootOrder: 0001,0000\n" +
			"Boot0000* UiApp FvVol(example)\n" +
			"Boot0001* debian HD(1,GPT,test)/File(\\EFI\\debian\\shimx64.efi)\n",
	}
}

func writeFixture(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func initialGRUB() []byte {
	return []byte("menuentry 'Debian' {\n  linux /boot/vmlinuz-" + testKernelRelease + " root=/dev/test ro quiet\n}\n")
}

func preparedGRUB() []byte {
	return []byte("menuentry 'Debian' {\n  linux /boot/vmlinuz-" + testKernelRelease + " root=/dev/test ro quiet ipv6.disable=1\n}\n")
}

func (f *bootFixture) Run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, strings.TrimSpace(command))
	if f.fail != "" && name == f.fail {
		return nil, errors.New("injected")
	}
	switch {
	case name == "dpkg-query" && len(args) == 2 && args[0] == "--search" && args[1] == f.paths.GRUBUpdate:
		return []byte("grub2-common: " + f.paths.GRUBUpdate + "\n"), nil
	case name == "dpkg-query" && len(args) == 2 && args[0] == "--search" && args[1] == f.paths.EFIBootManager:
		return []byte("efibootmgr: " + f.paths.EFIBootManager + "\n"), nil
	case name == "dpkg-query" && len(args) == 3 && args[0] == "--show" && args[2] == "grub2-common":
		return []byte("install ok installed\n"), nil
	case name == "dpkg-query" && len(args) == 3 && args[0] == "--show" && args[2] == "efibootmgr":
		return []byte("install ok installed\n"), nil
	case name == "dpkg-query" && len(args) == 3 && args[0] == "--show":
		if f.installed[args[2]] {
			return []byte("ii \n"), nil
		}
		return nil, errors.New("not installed")
	case name == "uname" && len(args) == 1 && args[0] == "-r":
		return []byte(f.release + "\n"), nil
	case name == "uname" && len(args) == 1 && args[0] == "-m":
		return []byte(f.arch + "\n"), nil
	case name == "findmnt":
		return []byte(`{"filesystems":[{"source":"/dev/test","fstype":"ext4","target":"` +
			filepath.Dir(filepath.Dir(f.paths.GRUBGenerated)) + `","options":"` + f.mountOptions + `"}]}`), nil
	case name == f.paths.GRUBUpdate:
		if f.mutate {
			if err := os.WriteFile(f.paths.GRUBGenerated, preparedGRUB(), 0o600); err != nil {
				f.t.Fatal(err)
			}
		}
		return []byte("grub updated\n"), nil
	case name == f.paths.EFIBootManager:
		return []byte(f.efiOutput), nil
	case command == "nft --json list tables":
		objects := ""
		if f.initramfsGuard {
			objects += `,{"table":{"family":"inet","name":"` + bootguard.TableName + `"}}`
		}
		if f.resumeGuard {
			objects += `,{"table":{"family":"inet","name":"` + resumeGuardTable + `"}}`
		}
		return []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}}` + objects + `]}`), nil
	case command == "nft --json list table inet "+bootguard.TableName && f.initramfsGuard:
		return []byte(`{"nftables":[` +
			`{"metainfo":{"json_schema_version":1}},` +
			`{"table":{"family":"inet","name":"nftfw_initramfs_guard","handle":1,"comment":"nftfw:initramfs-guard:v1"}},` +
			`{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"input_guard","handle":2,"type":"filter","hook":"input","prio":-310,"policy":"drop","comment":"nftfw:initramfs-input:v1"}},` +
			`{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"output_guard","handle":3,"type":"filter","hook":"output","prio":-310,"policy":"drop","comment":"nftfw:initramfs-output:v1"}},` +
			`{"chain":{"family":"inet","table":"nftfw_initramfs_guard","name":"forward_guard","handle":4,"type":"filter","hook":"forward","prio":-310,"policy":"drop","comment":"nftfw:initramfs-forward:v1"}}]}`), nil
	case command == "nft --json list table inet "+bootguard.TableName:
		return nil, errors.New("absent")
	case command == "nft --json list ruleset":
		objects := ""
		if f.initramfsGuard {
			objects += `,{"table":{"family":"inet","name":"` + bootguard.TableName + `"}}`
		}
		if f.resumeGuard {
			objects += `,{"table":{"family":"inet","name":"` + resumeGuardTable + `"}}`
		}
		return []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}}` + objects + `]}`), nil
	case command == "nft list table inet "+resumeGuardTable && f.resumeGuard:
		return []byte("table inet " + resumeGuardTable + "\n"), nil
	case command == "nft list table inet "+resumeGuardTable:
		return nil, errors.New("absent")
	case command == "nft delete table inet "+resumeGuardTable && f.resumeGuard:
		f.resumeGuard = false
		return nil, nil
	case command == "nft delete table inet "+resumeGuardTable:
		return nil, errors.New("absent")
	case name == "nft" && len(args) == 2 && args[0] == "--file" &&
		strings.HasSuffix(args[1], "setup-resume-guard.nft"):
		if !f.initramfsGuard || f.resumeGuard {
			return nil, errors.New("invalid swap")
		}
		f.initramfsGuard, f.resumeGuard = false, true
		return nil, nil
	default:
		return f.base.Run(ctx, input, name, args...)
	}
}

func TestManagedGRUBIdentityAndArgumentMatrix(t *testing.T) {
	fixture := newBootFixture(t)
	initial, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, false)
	if err != nil || initial.Prepared || initial.BootID != testBootID1 {
		t.Fatalf("initial observation failed: %#v %v", initial, err)
	}
	writeFixture(t, fixture.paths.GRUBFragment, []byte(grubFragmentData), 0o600)
	writeFixture(t, fixture.paths.BootHoldMarker, []byte(bootHoldMarkerData), 0o600)
	writeFixture(t, fixture.paths.GRUBGenerated, preparedGRUB(), 0o600)
	prepared, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, true)
	if err != nil || !prepared.Prepared {
		t.Fatalf("prepared observation failed: %#v %v", prepared, err)
	}
	for _, test := range []struct {
		name string
		line string
	}{
		{name: "duplicate", line: "ipv6.disable=1 ipv6.disable=1"},
		{name: "conflict", line: "ipv6.disable=0"},
		{name: "bare", line: "ipv6.disable"},
		{name: "quoted-conflict", line: "'ipv6.disable=0'"},
		{name: "unterminated", line: "'ipv6.disable=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte("linux /boot/vmlinuz-" + testKernelRelease + " root=/dev/test " + test.line + "\n")
			if err := verifyGeneratedGRUB(data, true, "vmlinuz-"+testKernelRelease); err == nil {
				t.Fatal("unsafe kernel argument was accepted")
			}
		})
	}
	quoted := []byte("linux /boot/vmlinuz-" + testKernelRelease + " root=/dev/test 'ipv6.disable=1'\n")
	if err := verifyGeneratedGRUB(quoted, true, "vmlinuz-"+testKernelRelease); err != nil {
		t.Fatalf("GRUB-equivalent quoted exact token was not counted exactly: %v", err)
	}
}

func TestManagedGRUBRefusesUnsafeIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *bootFixture)
	}{
		{name: "foreign-fragment", mutate: func(t *testing.T, f *bootFixture) {
			writeFixture(t, f.paths.GRUBFragment, []byte("foreign\n"), 0o600)
		}},
		{name: "systemd-boot", mutate: func(t *testing.T, f *bootFixture) {
			if err := os.MkdirAll(f.paths.SystemdBootEntries, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group-writable-config", mutate: func(t *testing.T, f *bootFixture) {
			if err := os.Chmod(f.paths.GRUBGenerated, 0o620); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink-config", mutate: func(t *testing.T, f *bootFixture) {
			if err := os.Remove(f.paths.GRUBGenerated); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(f.paths.BootKernelDir, "vmlinuz-"+testKernelRelease), f.paths.GRUBGenerated); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "read-only-mount", mutate: func(t *testing.T, f *bootFixture) { f.fail = "findmnt" }},
		{name: "multiple-grub-families", mutate: func(t *testing.T, f *bootFixture) {
			f.installed["grub-efi-amd64"] = true
		}},
		{name: "wrong-grub-family", mutate: func(t *testing.T, f *bootFixture) {
			f.installed = map[string]bool{"grub-efi-amd64": true}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootFixture(t)
			test.mutate(t, fixture)
			if _, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, false); err == nil {
				t.Fatal("unsafe boot identity was accepted")
			}
		})
	}
}

func TestManagedGRUBRefusesUnsupportedManagersFilesAndCommands(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *bootFixture)
	}{
		{name: "uki", mutate: func(t *testing.T, f *bootFixture) { mustMkdir(t, f.paths.UKIDir, 0o755) }},
		{name: "extlinux", mutate: func(t *testing.T, f *bootFixture) { mustMkdir(t, f.paths.ExtlinuxDir, 0o755) }},
		{name: "alternate-grub", mutate: func(t *testing.T, f *bootFixture) { mustMkdir(t, f.paths.AlternateGRUBDir, 0o755) }},
		{name: "unsafe-source-directory", mutate: func(t *testing.T, f *bootFixture) {
			if err := os.Chmod(f.paths.GRUBSourceDir, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "empty-update-command", mutate: func(t *testing.T, f *bootFixture) {
			writeFixture(t, f.paths.GRUBUpdate, nil, 0o755)
		}},
		{name: "non-executable-update-command", mutate: func(t *testing.T, f *bootFixture) {
			writeFixture(t, f.paths.GRUBUpdate, []byte("command\n"), 0o600)
		}},
		{name: "unowned-update-command", mutate: func(_ *testing.T, f *bootFixture) { f.fail = "dpkg-query" }},
		{name: "unsupported-architecture", mutate: func(_ *testing.T, f *bootFixture) { f.arch = "riscv64" }},
		{name: "invalid-kernel-release", mutate: func(_ *testing.T, f *bootFixture) { f.release = "invalid release" }},
		{name: "missing-active-kernel", mutate: func(t *testing.T, f *bootFixture) {
			if err := os.Remove(filepath.Join(f.paths.BootKernelDir, "vmlinuz-"+testKernelRelease)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootFixture(t)
			test.mutate(t, fixture)
			if _, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, false); err == nil {
				t.Fatal("unsupported boot identity was accepted")
			}
		})
	}
	fixture := newBootFixture(t)
	paths := fixture.paths
	paths.GRUBGenerated = "relative/grub.cfg"
	if _, err := inspectManagedGRUB(context.Background(), fixture, paths, false); err == nil {
		t.Fatal("non-fixed boot paths were accepted")
	}
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestManagedGRUBMountAndGeneratedConfigRefusalMatrix(t *testing.T) {
	fixture := newBootFixture(t)
	for _, test := range []struct {
		name string
		json string
	}{
		{name: "malformed", json: `{`},
		{name: "unknown-field", json: `{"filesystems":[],"extra":true}`},
		{name: "multiple", json: `{"filesystems":[{},{}]}`},
		{name: "remote", json: `{"filesystems":[{"source":"/dev/test","fstype":"nfs","target":"/","options":"rw"}]}`},
		{name: "non-device", json: `{"filesystems":[{"source":"pool/test","fstype":"ext4","target":"/","options":"rw"}]}`},
		{name: "read-only", json: `{"filesystems":[{"source":"/dev/test","fstype":"ext4","target":"/","options":"ro"}]}`},
		{name: "outside-target", json: `{"filesystems":[{"source":"/dev/test","fstype":"ext4","target":"/not-boot","options":"rw"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := systemRunnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
				return []byte(test.json), nil
			})
			if _, err := inspectBootMount(context.Background(), runner, fixture.paths, true); err == nil {
				t.Fatal("unsafe mount identity was accepted")
			}
		})
	}
	t.Run("sandbox-read-only-runtime-view", func(t *testing.T) {
		fixture := newBootFixture(t)
		strict, err := inspectBootMount(context.Background(), fixture, fixture.paths, true)
		if err != nil {
			t.Fatal(err)
		}
		fixture.mountOptions = "ro,nosuid,relatime"
		runtime, err := inspectBootMount(context.Background(), fixture, fixture.paths, false)
		if err != nil || runtime != strict {
			t.Fatalf("sandboxed runtime mount identity differs: %q %q %v", strict, runtime, err)
		}
		if _, err := inspectBootMount(context.Background(), fixture, fixture.paths, true); err == nil {
			t.Fatal("read-only sandbox view passed writable capability preflight")
		}
	})
	t.Run("stable-mount-option-normalization", func(t *testing.T) {
		options, readWrite, readOnly, valid := stableMountOptions(
			"rw,noexec,nodev,nosuid,seclabel,relatime",
		)
		if !valid || !readWrite || readOnly ||
			!reflect.DeepEqual(options, []string{"relatime", "seclabel"}) {
			t.Fatalf("stable mount options were not normalized exactly: %v %t %t %t", options, readWrite, readOnly, valid)
		}
		for _, value := range []string{"", "rw,rw", "rw,ro", "relatime"} {
			if _, _, _, accepted := stableMountOptions(value); accepted {
				t.Fatalf("ambiguous mount options %q were accepted", value)
			}
		}
	})
	for _, filesystem := range []string{"nfs", "nfs4", "cifs", "smb3", "sshfs", "9p", "ceph", "glusterfs"} {
		if !remoteFilesystem(filesystem) {
			t.Fatalf("remote filesystem %q was accepted", filesystem)
		}
	}
	if remoteFilesystem("ext4") {
		t.Fatal("local filesystem was classified as remote")
	}
	for _, data := range [][]byte{
		nil,
		[]byte("menuentry 'no linux' {}\n"),
		[]byte("linux /boot/vmlinuz-other ro ipv6.disable=1\n"),
		[]byte("linuxefi /boot/vmlinuz-" + testKernelRelease + " ro\n"),
	} {
		if err := verifyGeneratedGRUB(data, true, "vmlinuz-"+testKernelRelease); err == nil {
			t.Fatalf("invalid generated configuration was accepted: %q", data)
		}
	}
	linuxEFI := []byte("linuxefi /boot/vmlinuz-" + testKernelRelease + " ro ipv6.disable=1\n")
	if err := verifyGeneratedGRUB(linuxEFI, true, "vmlinuz-"+testKernelRelease); err != nil {
		t.Fatalf("valid linuxefi entry was refused: %v", err)
	}
}

func TestManagedGRUBProtectedReadAndRuntimeProofRefusals(t *testing.T) {
	fixture := newBootFixture(t)
	tooLarge := filepath.Join(filepath.Dir(fixture.paths.GRUBGenerated), "large")
	writeFixture(t, tooLarge, []byte("oversized"), 0o600)
	if _, _, err := readBootRegular(tooLarge, 1); err == nil {
		t.Fatal("oversized boot file was accepted")
	}
	hardlink := filepath.Join(filepath.Dir(fixture.paths.GRUBGenerated), "hardlink")
	if err := os.Link(fixture.paths.GRUBGenerated, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readBootRegular(fixture.paths.GRUBGenerated, 4<<20); err == nil {
		t.Fatal("multiply-linked boot file was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootID(fixture.paths.ProcCmdline); err == nil {
		t.Fatal("invalid boot ID was accepted")
	}

	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	for _, test := range []struct {
		name      string
		cmdline   string
		parameter string
		addresses string
	}{
		{name: "missing-token", cmdline: "root=/dev/test", parameter: "Y"},
		{name: "duplicate-token", cmdline: "ipv6.disable=1 ipv6.disable=1", parameter: "Y"},
		{name: "conflicting-token", cmdline: "ipv6.disable=0", parameter: "Y"},
		{name: "quoted-token", cmdline: "'ipv6.disable=1'", parameter: "Y"},
		{name: "kernel-parameter", cmdline: "ipv6.disable=1", parameter: "N"},
		{name: "ipv6-state", cmdline: "ipv6.disable=1", parameter: "Y", addresses: "00000000000000000000000000000001 01 80 10 80 lo"},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeFixture(t, fixture.paths.ProcCmdline, []byte(test.cmdline+"\n"), 0o600)
			writeFixture(t, fixture.paths.IPv6DisableParam, []byte(test.parameter+"\n"), 0o600)
			writeFixture(t, fixture.paths.ProcIfInet6, []byte(test.addresses), 0o600)
			if err := verifyRunningBoot(fixture.paths, testBootID1); err == nil {
				t.Fatal("invalid running boot proof was accepted")
			}
		})
	}
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ipv6.disable=1\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	if err := os.Remove(fixture.paths.ProcIfInet6); err != nil {
		t.Fatal(err)
	}
	if err := verifyRunningBoot(fixture.paths, testBootID1); err != nil {
		t.Fatalf("kernel-omitted IPv6 address file was refused: %v", err)
	}
	linkedTarget := filepath.Join(filepath.Dir(fixture.paths.ProcIfInet6), "linked-if-inet6")
	writeFixture(t, linkedTarget, nil, 0o600)
	if err := os.Symlink(linkedTarget, fixture.paths.ProcIfInet6); err != nil {
		t.Fatal(err)
	}
	if err := verifyRunningBoot(fixture.paths, testBootID1); err == nil {
		t.Fatal("linked IPv6 address proof was accepted")
	}
	if err := os.Remove(fixture.paths.ProcIfInet6); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.ProcIfInet6, make([]byte, (1<<20)+1), 0o600)
	if err := verifyRunningBoot(fixture.paths, testBootID1); err == nil {
		t.Fatal("oversized IPv6 address proof was accepted")
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID1+"\n"), 0o600)
	if err := verifyRunningBoot(fixture.paths, testBootID1); err == nil {
		t.Fatal("unchanged boot ID was accepted")
	}
	if err := os.Remove(fixture.paths.ProcCmdline); err != nil {
		t.Fatal(err)
	}
	if !runningKernelHasManagedDisable(fixture.paths) {
		t.Fatal("missing command line was not treated conservatively")
	}
}

func TestManagedGRUBTokenizationAndPreparedFragmentRefusals(t *testing.T) {
	words, err := grubWords(`linux /boot/kernel root=with\ space "quoted value" ''`)
	if err != nil || strings.Join(words, "|") != "linux|/boot/kernel|root=with space|quoted value|" {
		t.Fatalf("valid GRUB tokenization failed: %q %v", words, err)
	}
	if words, err := grubWords("  # comment"); err != nil || words != nil {
		t.Fatalf("GRUB comment was not ignored: %q %v", words, err)
	}
	fixture := newBootFixture(t)
	writeFixture(t, fixture.paths.GRUBFragment, []byte(grubFragmentData), 0o644)
	writeFixture(t, fixture.paths.GRUBGenerated, preparedGRUB(), 0o600)
	if _, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, true); err == nil {
		t.Fatal("world-readable managed fragment was accepted")
	}
	writeFixture(t, fixture.paths.GRUBFragment, []byte("foreign\n"), 0o600)
	if _, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, true); err == nil {
		t.Fatal("changed managed fragment was accepted")
	}
	if err := os.RemoveAll(fixture.paths.EFIFirmwareDir); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.EFIFirmwareDir, []byte("not a directory"), 0o600)
	if _, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, false); err == nil {
		t.Fatal("unsafe EFI firmware identity was accepted")
	}
	largeProc := filepath.Join(filepath.Dir(fixture.paths.ProcCmdline), "large-proc")
	writeFixture(t, largeProc, []byte("too large"), 0o600)
	if _, err := readProcFile(largeProc, 1); err == nil {
		t.Fatal("oversized runtime proof was accepted")
	}
	writeFixture(t, fixture.paths.ProcCmdline, []byte("ipv6.disable=0\n"), 0o600)
	if !runningKernelHasManagedDisable(fixture.paths) {
		t.Fatal("conflicting running argument was not treated conservatively")
	}
}

func preparedBootState(t *testing.T) (*bootFixture, *System, Journal) {
	t.Helper()
	fixture := newBootFixture(t)
	system, journalPath := managedBootSystem(t, fixture)
	engine := Engine{Executor: system, Journal: FileJournal{Path: journalPath}, NewID: func() string { return "boot-status" }}
	if _, err := engine.Run(context.Background(), "/provider.conf"); !errors.Is(err, ErrRebootRequired) {
		t.Fatalf("boot fixture did not reach reboot_required: %v", err)
	}
	journal, err := (FileJournal{Path: journalPath}).Read()
	if err != nil {
		t.Fatal(err)
	}
	return fixture, system, journal
}

func TestManagedBootStatusAndLifecycleRefuseChangedEvidence(t *testing.T) {
	fixture, system, journal := preparedBootState(t)
	if system.BootTransactionRequired(Plan{}) {
		t.Fatal("empty plan unexpectedly required a boot transaction")
	}
	if _, err := system.PendingBootStatus(context.Background(), Journal{}); err == nil {
		t.Fatal("invalid pending-boot journal was accepted")
	}
	writeFixture(t, fixture.paths.GRUBFragment, []byte("changed\n"), 0o600)
	if _, err := system.PendingBootStatus(context.Background(), journal); err == nil {
		t.Fatal("changed prepared fragment was accepted by status")
	}
	if err := system.VerifyBootResume(context.Background(), Plan{}); err == nil {
		t.Fatal("invalid boot resume plan was accepted")
	}
	if err := system.PrepareBoot(context.Background(), Plan{}); err == nil {
		t.Fatal("invalid boot preparation plan was accepted")
	}
	if err := system.FinalizeBootRollback(context.Background(), Journal{}); err == nil {
		t.Fatal("invalid rollback reboot journal was accepted")
	}
	if _, err := system.HandoffBootPolicy(context.Background(), Journal{}); err == nil {
		t.Fatal("invalid package boot handoff was accepted")
	}
}

func TestManagedBootStatusRefusesMissingProtectedBackup(t *testing.T) {
	_, system, journal := preparedBootState(t)
	if err := os.Remove(filepath.Join(journal.BackupDir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := system.PendingBootStatus(context.Background(), journal); err == nil {
		t.Fatal("missing protected boot backup was accepted")
	}
}

func TestManagedBootStatusRefusesInvalidRunningAndGuardProof(t *testing.T) {
	fixture, system, journal := preparedBootState(t)
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	if _, err := system.PendingBootStatus(context.Background(), journal); err == nil {
		t.Fatal("changed boot without kernel proof was accepted")
	}
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ipv6.disable=1\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	fixture.fail = system.Paths.InitramfsManager
	if _, err := system.PendingBootStatus(context.Background(), journal); err == nil {
		t.Fatal("failed native guard verification was accepted")
	}
}

func TestManagedBootPreparationFailureBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *bootFixture, *System, Plan)
	}{
		{name: "missing-manifest", mutate: func(t *testing.T, _ *bootFixture, _ *System, plan Plan) {
			private, err := privatePlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(private.BackupDir, "manifest.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "changed-generated-config", mutate: func(t *testing.T, f *bootFixture, _ *System, _ Plan) {
			writeFixture(t, f.paths.GRUBGenerated, append(initialGRUB(), []byte("# changed\n")...), 0o600)
		}},
		{name: "watchdog-start-failure", mutate: func(_ *testing.T, f *bootFixture, _ *System, _ Plan) {
			f.fail = "systemctl"
		}},
		{name: "initramfs-prepare-failure", mutate: func(_ *testing.T, f *bootFixture, s *System, _ Plan) {
			f.fail = s.Paths.InitramfsManager
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootFixture(t)
			system, _ := managedBootSystem(t, fixture)
			plan, err := system.Prepare(context.Background(), "/provider.conf")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := system.Backup(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, fixture, system, plan)
			if err := system.PrepareBoot(context.Background(), plan); err == nil {
				t.Fatal("boot preparation failure boundary was accepted")
			}
		})
	}
}

func TestManagedGRUBFragmentPublicationIsNoReplace(t *testing.T) {
	fixture := newBootFixture(t)
	if err := publishGRUBFragment(fixture.paths.GRUBFragment); err != nil {
		t.Fatalf("fixed fragment publication failed: %v", err)
	}
	if err := publishGRUBFragment(fixture.paths.GRUBFragment); err == nil || err.Error() != "SETUP_BOOT_FRAGMENT_FOREIGN" {
		t.Fatalf("existing fragment was not refused by no-replace publication: %v", err)
	}
}

func TestManagedGRUBAcceptsOneExactEFIIdentity(t *testing.T) {
	fixture := newBootFixture(t)
	if err := os.MkdirAll(fixture.paths.EFIFirmwareDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture.installed = map[string]bool{"grub-efi-amd64": true}
	if _, err := inspectManagedGRUB(context.Background(), fixture, fixture.paths, false); err != nil {
		t.Fatalf("one exact Debian EFI GRUB identity was refused: %v", err)
	}
}

func TestManagedGRUBEFIIdentityMatrix(t *testing.T) {
	validX64 := "BootCurrent: 0001\nBootOrder: 0001,0000\n" +
		"Boot0000* UiApp FvVol(example)\n" +
		"Boot0001* debian HD(1,GPT,test)/File(\\EFI\\debian\\shimx64.efi)\n"
	validArm64 := strings.ReplaceAll(validX64, "shimx64.efi", "shimaa64.efi")
	if err := verifyEFIBootOutput([]byte(validX64), "x86_64"); err != nil {
		t.Fatalf("valid amd64 EFI identity was refused: %v", err)
	}
	if err := verifyEFIBootOutput([]byte(validArm64), "arm64"); err != nil {
		t.Fatalf("valid arm64 EFI identity was refused: %v", err)
	}
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "missing-current", data: strings.Replace(validX64, "BootCurrent: 0001\n", "", 1)},
		{name: "duplicate-current", data: "BootCurrent: 0001\n" + validX64},
		{name: "malformed-current", data: strings.Replace(validX64, "BootCurrent: 0001", "BootCurrent: z001", 1)},
		{name: "network-entry", data: validX64 + "Boot0003* UEFI PXEv4 (MAC:test)/MAC(test)\n"},
		{name: "network-continuation", data: validX64 + "  dp: /MAC(test)\n"},
		{name: "boot-next", data: "BootNext: 0000\n" + validX64},
		{name: "wrong-first", data: strings.Replace(validX64, "BootOrder: 0001,0000", "BootOrder: 0000,0001", 1)},
		{name: "duplicate-order", data: strings.Replace(validX64, "BootOrder: 0001,0000", "BootOrder: 0001,0001", 1)},
		{name: "wrong-loader", data: strings.Replace(validX64, "shimx64.efi", "foreignx64.efi", 1)},
		{name: "non-debian", data: strings.Replace(validX64, " debian", " foreign", 1)},
		{name: "inactive-current", data: strings.Replace(validX64, "Boot0001*", "Boot0001 ", 1)},
		{name: "duplicate-entry", data: validX64 + "Boot0001* duplicate\n"},
		{name: "missing-ordered-entry", data: strings.Replace(validX64, "BootOrder: 0001,0000", "BootOrder: 0001,0002", 1)},
		{name: "nul", data: validX64 + "\x00"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyEFIBootOutput([]byte(test.data), "x86_64"); err == nil {
				t.Fatal("unsafe EFI boot identity was accepted")
			}
		})
	}
	if err := verifyEFIBootOutput([]byte(validX64), "ppc64le"); err == nil {
		t.Fatal("unsupported EFI architecture was accepted")
	}
}

func TestManagedGRUBReadDetectsIdentityRace(t *testing.T) {
	fixture := newBootFixture(t)
	_, _, err := readBootRegularHook(fixture.paths.GRUBGenerated, 4<<20, func() {
		writeFixture(t, fixture.paths.GRUBGenerated, append(initialGRUB(), []byte("# changed\n")...), 0o600)
	})
	if err == nil || err.Error() != "SETUP_BOOT_FILE_CHANGED" {
		t.Fatalf("boot file race was not detected: %v", err)
	}
}

func TestManagedGRUBUpdateTimeoutAndOutputBound(t *testing.T) {
	timed := &timedBootRunner{}
	if err := runGRUBUpdate(context.Background(), timed, "/usr/sbin/update-grub"); err != nil || timed.timeout != 2*time.Minute {
		t.Fatalf("GRUB update did not use its explicit bounded runner: %v %s", err, timed.timeout)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	blocked := systemRunnerFunc(func(ctx context.Context, _ []byte, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err := runGRUBUpdate(ctx, blocked, "/usr/sbin/update-grub"); err == nil {
		t.Fatal("canceled GRUB update was accepted")
	}
	oversized := systemRunnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return make([]byte, (1<<20)+1), nil
	})
	if err := runGRUBUpdate(context.Background(), oversized, "/usr/sbin/update-grub"); err == nil {
		t.Fatal("oversized GRUB update output was accepted")
	}
}

func managedBootSystem(t *testing.T, fixture *bootFixture) (*System, string) {
	t.Helper()
	system, paths := testSystem(t, fixture.base)
	paths.GRUBFragment = fixture.paths.GRUBFragment
	paths.GRUBSourceDir = fixture.paths.GRUBSourceDir
	paths.GRUBGenerated = fixture.paths.GRUBGenerated
	paths.GRUBUpdate = fixture.paths.GRUBUpdate
	paths.BootKernelDir = fixture.paths.BootKernelDir
	paths.ProcCmdline = fixture.paths.ProcCmdline
	paths.ProcBootID = fixture.paths.ProcBootID
	paths.IPv6DisableParam = fixture.paths.IPv6DisableParam
	paths.ProcIfInet6 = fixture.paths.ProcIfInet6
	paths.BootHoldMarker = fixture.paths.BootHoldMarker
	paths.BootHoldReady = fixture.paths.BootHoldReady
	paths.BootHoldRelease = fixture.paths.BootHoldRelease
	paths.SystemdBootEntries = fixture.paths.SystemdBootEntries
	paths.UKIDir = fixture.paths.UKIDir
	paths.ExtlinuxDir = fixture.paths.ExtlinuxDir
	paths.AlternateGRUBDir = fixture.paths.AlternateGRUBDir
	paths.EFIFirmwareDir = fixture.paths.EFIFirmwareDir
	system.Paths = paths
	system.Runner = fixture
	system.InspectBoot = nil
	baseDiscover := system.Discover
	journalPath := filepath.Join(paths.StateDir, "setup", "journal.json")
	system.Discover = func(ctx context.Context) (discovery.Snapshot, error) {
		snapshot, err := baseDiscover(ctx)
		if _, statErr := os.Lstat(journalPath); statErr == nil {
			snapshot.ExistingNFTFWState = true
		}
		if fixture.initramfsGuard || fixture.resumeGuard {
			snapshot.ForeignNFTables = true
		}
		return snapshot, err
	}
	return system, journalPath
}

func activateManagedBootHold(t *testing.T, system *System, journalPath string, fixture *bootFixture) {
	t.Helper()
	fixture.initramfsGuard = true
	// The packaged hold runs with ProtectSystem=strict, so findmnt projects the
	// otherwise writable boot filesystem as read-only inside that verifier.
	originalOptions := fixture.mountOptions
	fixture.mountOptions = "ro,nosuid,relatime"
	if err := system.WaitBootHold(context.Background(), FileJournal{Path: journalPath}); err != nil {
		t.Fatalf("managed boot hold did not publish the resume boundary: %v", err)
	}
	fixture.mountOptions = originalOptions
	if !fixture.resumeGuard || fixture.initramfsGuard {
		t.Fatal("managed boot hold did not atomically replace the initramfs guard")
	}
}

func TestManagedBootTwoPassTransaction(t *testing.T) {
	fixture := newBootFixture(t)
	system, journalPath := managedBootSystem(t, fixture)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine := Engine{
		Executor: system, Journal: FileJournal{Path: journalPath},
		NewID: func() string { return "boot-two-pass" },
		Now:   func() time.Time { now = now.Add(time.Second); return now },
	}
	plan, err := engine.Run(context.Background(), "/provider.conf")
	if !errors.Is(err, ErrRebootRequired) || plan.Summary.BootPolicy != ManagedBootPolicy {
		t.Fatalf("first pass did not stop for reboot: %#v %v", plan.Summary, err)
	}
	journal, readErr := (FileJournal{Path: journalPath}).Read()
	if readErr != nil || journal.Status != "reboot_required" || journal.Phase != PhaseBootPrep ||
		journal.Generation != 0 || journal.Committed {
		t.Fatalf("invalid reboot journal: %#v %v", journal, readErr)
	}
	if status, statusErr := system.PendingBootStatus(context.Background(), journal); statusErr != nil || status != "reboot_required" {
		t.Fatalf("same-boot status was not reboot_required: %q %v", status, statusErr)
	}
	if state, stateErr := protectedFixedRuntimeState(fixture.paths.BootHoldMarker, bootHoldMarkerData); stateErr != nil || !state {
		t.Fatalf("first pass did not publish the exact persistent boot hold: %t %v", state, stateErr)
	}
	manifest, manifestErr := readBackup(journal.BackupDir)
	if manifestErr != nil || manifest.Boot == nil ||
		!reflect.DeepEqual(manifest.Boot.ResumeEndpointIPv4, []string{"198.51.100.8"}) {
		t.Fatalf("first pass did not bind the resolved endpoint set: %#v %v", manifest.Boot, manifestErr)
	}
	journalData, marshalErr := json.Marshal(journal)
	if marshalErr != nil || bytes.Contains(journalData, []byte("198.51.100.8")) ||
		bytes.Contains(journalData, []byte("vpn.example.test")) {
		t.Fatalf("public journal exposed protected endpoint identity: %s %v", journalData, marshalErr)
	}
	resolveCalls := 0
	system.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		resolveCalls++
		return nil, errors.New("DNS is blocked by the resume guard")
	}
	for _, forbidden := range []string{"nft --file", "systemctl restart docker.service", "wg set", "ip -4 route replace"} {
		if strings.Contains(strings.Join(fixture.commands, "\n"), forbidden) {
			t.Fatalf("pre-reboot pass crossed mutation boundary %q", forbidden)
		}
	}
	for _, path := range []string{system.Paths.Config, system.Paths.Intent, system.Paths.VPN, system.Paths.Sysctl} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pre-reboot pass published managed runtime file %s", path)
		}
	}
	if _, sameBootErr := engine.Run(context.Background(), "/provider.conf"); !errors.Is(sameBootErr, ErrRebootRequired) {
		t.Fatalf("same-boot reentry did not remain reboot-required: %v", sameBootErr)
	}
	if resolveCalls != 0 {
		t.Fatalf("same-boot reentry attempted DNS under the prepared transaction: %d", resolveCalls)
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ro ipv6.disable=1 quiet\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	activateManagedBootHold(t, system, journalPath, fixture)
	if status, statusErr := system.PendingBootStatus(context.Background(), journal); statusErr != nil || status != "resume_ready" {
		t.Fatalf("changed-boot status was not resume_ready: %q %v", status, statusErr)
	}
	plan, err = engine.Run(context.Background(), "/provider.conf")
	if err != nil || plan.Summary.BootPolicy != ManagedBootPolicy {
		t.Fatalf("resume did not complete original transaction: %#v %v", plan.Summary, err)
	}
	if resolveCalls != 0 {
		t.Fatalf("post-reboot resume attempted DNS under the temporary guard: %d", resolveCalls)
	}
	journal, readErr = (FileJournal{Path: journalPath}).Read()
	if readErr != nil || journal.Status != "complete" || !journal.Committed || journal.Generation == 0 {
		t.Fatalf("invalid completed journal: %#v %v", journal, readErr)
	}
	if _, markerErr := os.Lstat(fixture.paths.BootHoldMarker); !errors.Is(markerErr, os.ErrNotExist) {
		t.Fatalf("completed setup retained its transient boot hold marker: %v", markerErr)
	}
}

func TestManagedBootResumeEndpointIdentityFailsClosed(t *testing.T) {
	fixture, system, journal := preparedBootState(t)
	manifest, err := readBackup(journal.BackupDir)
	if err != nil || manifest.Boot == nil {
		t.Fatal(err)
	}
	manifest.Boot.ResumeEndpointIPv4 = []string{"198.51.100.9"}
	if err := writeBackupManifest(manifest); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ro ipv6.disable=1\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	fixture.initramfsGuard = true
	if err := system.WaitBootHold(context.Background(), FileJournal{
		Path: filepath.Join(system.Paths.StateDir, "setup", "journal.json"),
	}); err != nil {
		t.Fatalf("valid guard could not reach the resume boundary: %v", err)
	}
	if _, err := system.Prepare(context.Background(), "/provider.conf"); err == nil ||
		err.Error() != "SETUP_RESUME_STATE_INVALID" {
		t.Fatalf("changed protected endpoint identity was accepted: %v", err)
	}
}

func TestBootResumeEndpointCanonicalMatrix(t *testing.T) {
	if !validResumeEndpoints([]string{"198.51.100.8", "203.0.113.9"}) {
		t.Fatal("canonical protected endpoint set was refused")
	}
	for _, values := range [][]string{
		nil,
		{"198.51.100.8", "198.51.100.8"},
		{"203.0.113.9", "198.51.100.8"},
		{"198.051.100.8"},
		{"127.0.0.1"},
		{"0.0.0.0"},
		{"224.0.0.1"},
		{"169.254.1.1"},
		{"2001:db8::1"},
	} {
		if validResumeEndpoints(values) {
			t.Fatalf("unsafe protected endpoint set was accepted: %#v", values)
		}
	}
}

func TestBootResumeDockerSnapshotCanonicalMatrix(t *testing.T) {
	valid := []config.DockerNetwork{{
		Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
		DynamicBridge: true, Subnets: []string{"172.17.0.0/16"},
		Gateways: []string{"172.17.0.1"},
	}}
	if !validResumeDockerState(true, true, valid) ||
		!validResumeDockerState(false, true, nil) {
		t.Fatal("canonical retained Docker state was refused")
	}
	for _, test := range []struct {
		name     string
		present  bool
		clean    bool
		networks []config.DockerNetwork
	}{
		{name: "not-clean", present: true, networks: valid},
		{name: "present-without-networks", present: true, clean: true},
		{name: "absent-with-empty-array", clean: true, networks: []config.DockerNetwork{}},
		{name: "static-bridge", present: true, clean: true, networks: []config.DockerNetwork{{
			Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
			Subnets: []string{"172.17.0.0/16"}, Gateways: []string{"172.17.0.1"},
		}}},
		{name: "noncanonical-subnet", present: true, clean: true, networks: []config.DockerNetwork{{
			Name: "bridge", Driver: "bridge", BridgeInterface: "docker0", DynamicBridge: true,
			Subnets: []string{"172.17.1.0/16"}, Gateways: []string{"172.17.0.1"},
		}}},
		{name: "broadcast-gateway", present: true, clean: true, networks: []config.DockerNetwork{{
			Name: "bridge", Driver: "bridge", BridgeInterface: "docker0", DynamicBridge: true,
			Subnets: []string{"172.17.0.0/16"}, Gateways: []string{"172.17.255.255"},
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if validResumeDockerState(test.present, test.clean, test.networks) {
				t.Fatal("unsafe retained Docker state was accepted")
			}
		})
	}
}

func TestResumeGuardRenderingAndProtectedBackup(t *testing.T) {
	setupGuard, err := renderGuard(
		"eth0", "nftfw0", "0xca6c", 51820,
		[]string{"198.51.100.8/32"}, []string{"192.168.1.0/24"}, []int{22},
	)
	if err != nil {
		t.Fatal(err)
	}
	resumeGuard, err := renderResumeGuard(setupGuard)
	if err != nil || !bytes.HasPrefix(resumeGuard, []byte("table inet "+resumeGuardTable+" {\n")) ||
		bytes.Contains(resumeGuard, []byte("table inet nftfw_setup_guard {")) ||
		!bytes.Contains(resumeGuard, []byte("nftfw:setup-resume-guard:v1")) {
		t.Fatalf("setup guard was not projected to one explicit resume identity: %v\n%s", err, resumeGuard)
	}
	for _, invalid := range [][]byte{
		nil,
		[]byte("table inet nftfw_setup_guard {}\n"),
		append(append([]byte(nil), setupGuard...), []byte("table inet nftfw_setup_guard {\n")...),
		bytes.Replace(setupGuard, []byte("nftfw_setup_guard"), []byte(resumeGuardTable), 1),
	} {
		if _, err := renderResumeGuard(invalid); err == nil {
			t.Fatalf("invalid setup guard was accepted for resume: %q", invalid)
		}
	}

	directory := t.TempDir()
	digest, err := publishResumeGuard(directory, resumeGuard)
	if err != nil || !validSHA256(digest) {
		t.Fatalf("protected resume guard publication failed: %s %v", digest, err)
	}
	manifest := backupManifest{
		Path: directory,
		Boot: &bootBackup{ResumeGuardSHA256: digest},
	}
	read, err := readResumeGuard(directory, manifest)
	if err != nil || !bytes.Equal(read, resumeGuard) {
		t.Fatalf("protected resume guard could not be read exactly: %v", err)
	}
	if _, err := publishResumeGuard(directory, resumeGuard); err == nil {
		t.Fatal("protected resume guard publication overwrote an existing payload")
	}
	path := filepath.Join(directory, resumeGuardFilename)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readResumeGuard(directory, manifest); err == nil {
		t.Fatal("group-readable resume guard was accepted")
	}
	writeFixture(t, path, append([]byte(nil), resumeGuard...), 0o600)
	changed := append([]byte(nil), resumeGuard...)
	changed[len(changed)-2] ^= 1
	writeFixture(t, path, changed, 0o600)
	if _, err := readResumeGuard(directory, manifest); err == nil {
		t.Fatal("changed resume guard was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	writeFixture(t, foreign, resumeGuard, 0o600)
	if err := os.Symlink(foreign, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readResumeGuard(directory, manifest); err == nil {
		t.Fatal("symlinked resume guard was accepted")
	}
}

func TestResumeGuardBackupInputBounds(t *testing.T) {
	if _, err := publishResumeGuard("relative", []byte("x")); err == nil {
		t.Fatal("relative resume backup path was accepted")
	}
	if _, err := publishResumeGuard(t.TempDir(), nil); err == nil {
		t.Fatal("empty resume guard was accepted")
	}
	if _, err := publishResumeGuard(t.TempDir(), make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("oversized resume guard was accepted")
	}
}

func TestManagedBootPostRebootFailureRequiresRollbackReboot(t *testing.T) {
	fixture := newBootFixture(t)
	system, journalPath := managedBootSystem(t, fixture)
	engine := Engine{
		Executor: system, Journal: FileJournal{Path: journalPath},
		NewID: func() string { return "post-reboot-failure" },
	}
	if _, err := engine.Run(context.Background(), "/provider.conf"); !errors.Is(err, ErrRebootRequired) {
		t.Fatalf("first pass did not require reboot: %v", err)
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ipv6.disable=1 ro\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	activateManagedBootHold(t, system, journalPath, fixture)
	fixture.base.fail = "nft --check --file"
	if _, err := engine.Run(context.Background(), "/provider.conf"); !errors.Is(err, ErrRollbackRebootRequired) {
		t.Fatalf("post-reboot failure did not publish rollback reboot requirement: %v", err)
	}
	journal, err := (FileJournal{Path: journalPath}).Read()
	if err != nil || journal.Status != "rollback_reboot_required" || journal.Phase != PhaseFailed {
		t.Fatalf("rollback reboot journal invalid: %#v %v", journal, err)
	}
	if reboot, handoffErr := system.HandoffBootPolicy(context.Background(), journal); handoffErr != nil || !reboot {
		t.Fatalf("exact already-restored package handoff was refused: %t %v", reboot, handoffErr)
	}
	if err := system.FinalizeBootRollback(context.Background(), journal); err == nil ||
		err.Error() != "SETUP_ROLLBACK_REBOOT_STILL_REQUIRED" {
		t.Fatalf("running disabled kernel was terminalized without a reboot: %v", err)
	}
	writeFixture(t, fixture.paths.GRUBFragment, []byte(grubFragmentData), 0o600)
	if _, handoffErr := system.HandoffBootPolicy(context.Background(), journal); handoffErr == nil {
		t.Fatal("changed already-restored package handoff state was accepted")
	}
	if err := os.Remove(fixture.paths.GRUBFragment); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID3+"\n"), 0o600)
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ro\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("N\n"), 0o600)
	fixture.fail = system.Paths.InitramfsManager
	if err := system.FinalizeBootRollback(context.Background(), journal); err == nil {
		t.Fatal("failed disabled native-guard verification was accepted")
	}
	fixture.fail = ""
	if err := system.FinalizeBootRollback(context.Background(), journal); err != nil {
		t.Fatalf("restored next boot was not recognized: %v", err)
	}
	if !strings.Contains(strings.Join(fixture.commands, "\n"),
		"sysctl -w net.ipv6.conf.lo.disable_ipv6=0") {
		t.Fatal("post-reboot finalizer did not restore the deferred IPv6 sysctl state")
	}
}

func TestManagedBootUpdateFailureRestoresExactly(t *testing.T) {
	fixture := newBootFixture(t)
	fixture.fail = fixture.paths.GRUBUpdate
	system, journalPath := managedBootSystem(t, fixture)
	engine := Engine{
		Executor: system, Journal: FileJournal{Path: journalPath},
		NewID: func() string { return "boot-update-failure" },
	}
	if _, err := engine.Run(context.Background(), "/provider.conf"); err == nil ||
		err.Error() != "SETUP_BOOT_UPDATE_FAILED" {
		t.Fatalf("unexpected update failure: %v", err)
	}
	if _, err := os.Lstat(fixture.paths.GRUBFragment); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed update retained owned fragment: %v", err)
	}
	if got, err := os.ReadFile(fixture.paths.GRUBGenerated); err != nil || string(got) != string(initialGRUB()) {
		t.Fatalf("failed update did not restore exact generated config: %v %q", err, got)
	}
	if _, err := os.Lstat(fixture.paths.BootHoldMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed update retained the transient boot hold marker: %v", err)
	}
	journal, err := (FileJournal{Path: journalPath}).Read()
	if err != nil || journal.Status != "rolled_back" || journal.Phase != PhaseFailed {
		t.Fatalf("failed update did not terminally roll back: %#v %v", journal, err)
	}
}

func TestManagedBootPackageHandoffRestoresOnlyBootOwnership(t *testing.T) {
	fixture := newBootFixture(t)
	system, journalPath := managedBootSystem(t, fixture)
	engine := Engine{
		Executor: system, Journal: FileJournal{Path: journalPath},
		NewID: func() string { return "boot-package-handoff" },
	}
	if _, err := engine.Run(context.Background(), "/provider.conf"); !errors.Is(err, ErrRebootRequired) {
		t.Fatalf("first pass did not require reboot: %v", err)
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ipv6.disable=1 ro\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	activateManagedBootHold(t, system, journalPath, fixture)
	if _, err := engine.Run(context.Background(), "/provider.conf"); err != nil {
		t.Fatalf("setup did not complete before package handoff: %v", err)
	}
	journal, err := (FileJournal{Path: journalPath}).Read()
	if err != nil {
		t.Fatal(err)
	}
	configBefore := append([]byte(nil), mustRead(t, system.Paths.Config)...)
	manifest, err := readBackup(journal.BackupDir)
	if err != nil || manifest.Boot == nil {
		t.Fatal(err)
	}
	originalPreparedDigest := manifest.Boot.PreparedGeneratedSHA256
	manifest.Boot.PreparedGeneratedSHA256 = ""
	if err := writeBackupManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := system.HandoffBootPolicy(context.Background(), journal); err == nil ||
		err.Error() != "SETUP_BOOT_HANDOFF_STATE_INVALID" {
		t.Fatalf("handoff accepted an incomplete protected manifest: %v", err)
	}
	manifest.Boot.PreparedGeneratedSHA256 = originalPreparedDigest
	if err := writeBackupManifest(manifest); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.GRUBGenerated, initialGRUB(), 0o600)
	if _, err := system.HandoffBootPolicy(context.Background(), journal); err == nil ||
		err.Error() != "SETUP_BOOT_HANDOFF_STATE_INVALID" {
		t.Fatalf("handoff accepted changed prepared GRUB state: %v", err)
	}
	writeFixture(t, fixture.paths.GRUBGenerated, preparedGRUB(), 0o600)
	fixture.fail = system.Paths.InitramfsManager
	if _, err := system.HandoffBootPolicy(context.Background(), journal); err == nil ||
		err.Error() != "SETUP_BOOT_HANDOFF_INITRAMFS_FAILED" {
		t.Fatalf("failed package initramfs handoff was accepted: %v", err)
	}
	fixture.fail = ""
	reboot, err := system.HandoffBootPolicy(context.Background(), journal)
	if err != nil || !reboot {
		t.Fatalf("package handoff did not record running-kernel reboot need: %t %v", reboot, err)
	}
	if _, err := os.Lstat(fixture.paths.GRUBFragment); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("package handoff retained GRUB fragment: %v", err)
	}
	if _, err := os.Lstat(fixture.paths.BootHoldMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("package handoff retained boot hold marker: %v", err)
	}
	if got := mustRead(t, fixture.paths.GRUBGenerated); string(got) != string(initialGRUB()) {
		t.Fatalf("package handoff did not restore exact generated config: %q", got)
	}
	if got := mustRead(t, system.Paths.Config); string(got) != string(configBefore) {
		t.Fatal("boot-only package handoff changed managed firewall configuration")
	}
	journal.Status, journal.Phase = "rollback_reboot_required", PhaseFailed
	if reboot, err := system.HandoffBootPolicy(context.Background(), journal); err != nil || !reboot {
		t.Fatalf("exact package boot handoff was not idempotent: %t %v", reboot, err)
	}
}

func TestManagedBootHoldResumeReleaseHandshake(t *testing.T) {
	fixture := newBootFixture(t)
	system, journalPath := managedBootSystem(t, fixture)
	engine := Engine{
		Executor: system, Journal: FileJournal{Path: journalPath},
		NewID: func() string { return "boot-hold-handshake" },
	}
	if _, err := engine.Run(context.Background(), "/provider.conf"); !errors.Is(err, ErrRebootRequired) {
		t.Fatalf("first pass did not require reboot: %v", err)
	}
	writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
	writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ro ipv6.disable=1\n"), 0o600)
	writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
	fixture.initramfsGuard = true

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- system.WaitBootHold(ctx, FileJournal{Path: journalPath})
	}()
	waitForRuntimeState(t, ctx, fixture.paths.BootHoldReady, bootHoldReadyData, true)
	if err := system.releaseBootHold(ctx); err != nil {
		t.Fatalf("valid local resume could not release boot hold: %v", err)
	}
	if err := <-waitResult; err != nil {
		t.Fatalf("boot hold waiter did not complete its release handshake: %v", err)
	}
	for _, path := range []string{fixture.paths.BootHoldReady, fixture.paths.BootHoldRelease} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("boot hold handshake retained runtime state %s: %v", path, err)
		}
	}
	if err := system.releaseBootHold(context.Background()); err != nil {
		t.Fatalf("already-released boot hold was not idempotent: %v", err)
	}
}

func TestManagedBootHoldProcessDeathReentryAndContradictions(t *testing.T) {
	for _, state := range []struct {
		name      string
		initramfs bool
		resume    bool
		wantOK    bool
	}{
		{name: "after-atomic-swap", resume: true, wantOK: true},
		{name: "before-atomic-swap", initramfs: true, wantOK: true},
		{name: "neither-guard", wantOK: false},
		{name: "both-guards", initramfs: true, resume: true, wantOK: false},
	} {
		t.Run(state.name, func(t *testing.T) {
			fixture, system, _ := preparedBootState(t)
			writeFixture(t, fixture.paths.ProcBootID, []byte(testBootID2+"\n"), 0o600)
			writeFixture(t, fixture.paths.ProcCmdline, []byte("root=/dev/test ro ipv6.disable=1\n"), 0o600)
			writeFixture(t, fixture.paths.IPv6DisableParam, []byte("Y\n"), 0o600)
			fixture.initramfsGuard, fixture.resumeGuard = state.initramfs, state.resume
			store := FileJournal{Path: filepath.Join(system.Paths.StateDir, "setup", "journal.json")}
			err := system.WaitBootHold(context.Background(), store)
			if !state.wantOK {
				if err == nil {
					t.Fatal("contradictory guard state was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("recoverable process-death boundary was refused: %v", err)
			}
			if !fixture.resumeGuard || fixture.initramfsGuard {
				t.Fatal("resume guard was not the sole surviving table")
			}
			if err := system.WaitBootHold(context.Background(), store); err != nil {
				t.Fatalf("published readiness was not restart-idempotent: %v", err)
			}
		})
	}
}

func TestManagedBootHoldRuntimeStateRefusalMatrix(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state")
	if present, err := protectedFixedRuntimeState(path, bootHoldReadyData); err != nil || present {
		t.Fatalf("absent runtime state was not inert: %t %v", present, err)
	}
	writeFixture(t, path, []byte(bootHoldReadyData), 0o600)
	if present, err := protectedFixedRuntimeState(path, bootHoldReadyData); err != nil || !present {
		t.Fatalf("exact runtime state was refused: %t %v", present, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign")
	writeFixture(t, foreign, []byte(bootHoldReadyData), 0o600)
	if err := os.Symlink(foreign, path); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedFixedRuntimeState(path, bootHoldReadyData); err == nil {
		t.Fatal("symlinked runtime state was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{name: "wrong-mode", data: []byte(bootHoldReadyData), mode: 0o640},
		{name: "wrong-content", data: []byte("xftfw.setup-boot-hold-ready.v1\n"), mode: 0o600},
		{name: "wrong-size", data: []byte(bootHoldReadyData + "x"), mode: 0o600},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeFixture(t, path, test.data, test.mode)
			if _, err := protectedFixedRuntimeState(path, bootHoldReadyData); err == nil {
				t.Fatal("unsafe runtime state was accepted")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		})
	}
	writeFixture(t, path, []byte(bootHoldReadyData), 0o600)
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedFixedRuntimeState(path, bootHoldReadyData); err == nil {
		t.Fatal("multiply-linked runtime state was accepted")
	}
}

func TestManagedBootHoldInvalidStateFailsClosed(t *testing.T) {
	fixture := newBootFixture(t)
	system, journalPath := managedBootSystem(t, fixture)
	foreign := filepath.Join(filepath.Dir(fixture.paths.BootHoldReady), "foreign-ready")
	writeFixture(t, foreign, []byte(bootHoldReadyData), 0o600)
	if err := os.Symlink(foreign, fixture.paths.BootHoldReady); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := system.WaitBootHold(ctx, FileJournal{Path: journalPath}); err == nil ||
		err.Error() != "SETUP_BOOT_HOLD_STATE_INVALID" {
		t.Fatalf("unsafe ready state did not fail closed: %v", err)
	}
	if err := os.Remove(fixture.paths.BootHoldReady); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.BootHoldRelease, []byte("invalid\n"), 0o600)
	if err := system.releaseBootHold(context.Background()); err == nil ||
		err.Error() != "SETUP_BOOT_HOLD_STATE_INVALID" {
		t.Fatalf("unsafe release state did not fail closed: %v", err)
	}
	if err := os.Remove(fixture.paths.BootHoldRelease); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture.paths.BootHoldRelease, []byte(bootHoldReleaseData), 0o600)
	if err := system.releaseBootHold(context.Background()); err != nil {
		t.Fatalf("stale exact release state was not cleaned: %v", err)
	}
	if _, err := os.Lstat(fixture.paths.BootHoldRelease); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale exact release state remains: %v", err)
	}
}

func TestManagedDockerHoldHandshakeAndCleanup(t *testing.T) {
	fixture := newBootFixture(t)
	system, _ := managedBootSystem(t, fixture)
	if err := publishBootHoldMarker(system.Paths.BootHoldMarker); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, system.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, system.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	if err := os.MkdirAll(filepath.Dir(system.Paths.DockerHoldReady), 0o750); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- system.WaitDockerHold(ctx) }()
	waitForRuntimeState(t, ctx, system.Paths.DockerHoldReady, dockerHoldReadyData, true)
	if _, err := os.Lstat(system.Paths.DockerHoldRelease); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Docker was released before managed ownership: %v", err)
	}
	if err := system.releaseDockerHold(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("Docker hold did not finish after exact release: %v", err)
	}
	if err := system.cleanupDockerHold(ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{system.Paths.DockerHoldReady, system.Paths.DockerHoldRelease} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Docker hold retained runtime state %s: %v", path, err)
		}
	}
}

func TestManagedDockerHoldCleanupReleasesBlockedUnit(t *testing.T) {
	fixture := newBootFixture(t)
	system, _ := managedBootSystem(t, fixture)
	writeFixture(t, system.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
	writeFixture(t, system.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
	writeFixture(t, system.Paths.DockerHoldReady, []byte(dockerHoldReadyData), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	unitExited := make(chan error, 1)
	go func() {
		for {
			released, err := protectedFixedRuntimeState(system.Paths.DockerHoldRelease, dockerHoldReleaseData)
			if err != nil {
				unitExited <- err
				return
			}
			if released {
				if err := os.Remove(system.Paths.DockerHoldReady); err != nil {
					unitExited <- err
					return
				}
				unitExited <- syncSetupDirectory(filepath.Dir(system.Paths.DockerHoldReady))
				return
			}
			select {
			case <-ctx.Done():
				unitExited <- ctx.Err()
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	if err := system.cleanupDockerHold(ctx); err != nil {
		t.Fatalf("cleanup did not release a blocked Docker unit: %v", err)
	}
	if err := <-unitExited; err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{system.Paths.DockerHoldReady, system.Paths.DockerHoldRelease} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Docker cleanup retained %s: %v", path, err)
		}
	}
}

func TestManagedDockerHoldInterruptedStateFailsClosed(t *testing.T) {
	newGeneratedSystem := func(t *testing.T) *System {
		t.Helper()
		fixture := newBootFixture(t)
		system, _ := managedBootSystem(t, fixture)
		if err := publishBootHoldMarker(system.Paths.BootHoldMarker); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, system.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
		writeFixture(t, system.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
		if err := os.MkdirAll(filepath.Dir(system.Paths.DockerHoldReady), 0o750); err != nil {
			t.Fatal(err)
		}
		return system
	}

	t.Run("wait-canceled-after-ready", func(t *testing.T) {
		system := newGeneratedSystem(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := system.WaitDockerHold(ctx); err == nil || err.Error() != "SETUP_DOCKER_HOLD_CANCELED" {
			t.Fatalf("canceled Docker hold was not reported exactly: %v", err)
		}
		present, err := protectedFixedRuntimeState(system.Paths.DockerHoldReady, dockerHoldReadyData)
		if err != nil || !present {
			t.Fatalf("canceled hold did not retain its fail-closed readiness evidence: %t %v", present, err)
		}
	})

	t.Run("invalid-release", func(t *testing.T) {
		system := newGeneratedSystem(t)
		writeFixture(t, system.Paths.DockerHoldRelease, []byte("invalid\n"), 0o600)
		if err := system.WaitDockerHold(context.Background()); err == nil ||
			err.Error() != "SETUP_DOCKER_HOLD_STATE_INVALID" {
			t.Fatalf("invalid release state was accepted: %v", err)
		}
	})

	t.Run("cleanup-canceled", func(t *testing.T) {
		system := newGeneratedSystem(t)
		writeFixture(t, system.Paths.DockerHoldReady, []byte(dockerHoldReadyData), 0o600)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := system.cleanupDockerHold(ctx); err == nil ||
			err.Error() != "SETUP_DOCKER_HOLD_RELEASE_CANCELED" {
			t.Fatalf("canceled cleanup was not reported exactly: %v", err)
		}
		present, err := protectedFixedRuntimeState(system.Paths.DockerHoldRelease, dockerHoldReleaseData)
		if err != nil || !present {
			t.Fatalf("canceled cleanup did not retain exact release evidence: %t %v", present, err)
		}
	})

	for _, state := range []struct {
		name string
		path func(*System) string
	}{
		{name: "unsafe-ready", path: func(s *System) string { return s.Paths.DockerHoldReady }},
		{name: "unsafe-release", path: func(s *System) string { return s.Paths.DockerHoldRelease }},
	} {
		t.Run(state.name, func(t *testing.T) {
			system := newGeneratedSystem(t)
			writeFixture(t, state.path(system), []byte("invalid\n"), 0o600)
			if err := system.cleanupDockerHold(context.Background()); err == nil ||
				err.Error() != "SETUP_DOCKER_HOLD_STATE_INVALID" {
				t.Fatalf("unsafe cleanup state was accepted: %v", err)
			}
		})
	}

	t.Run("stale-release-without-generator", func(t *testing.T) {
		fixture := newBootFixture(t)
		system, _ := managedBootSystem(t, fixture)
		writeFixture(t, system.Paths.DockerHoldRelease, []byte(dockerHoldReleaseData), 0o600)
		if err := system.cleanupDockerHold(context.Background()); err != nil {
			t.Fatalf("exact stale release could not be cleaned: %v", err)
		}
		if _, err := os.Lstat(system.Paths.DockerHoldRelease); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale release remains: %v", err)
		}
	})
}

func TestPublishFixedRuntimeFileIsExclusiveAndIdempotent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state")
	if err := publishFixedRuntimeFile(path, []byte(bootHoldReadyData)); err != nil {
		t.Fatal(err)
	}
	if err := publishFixedRuntimeFile(path, []byte(bootHoldReadyData)); err != nil {
		t.Fatalf("exact fixed state was not idempotent: %v", err)
	}
	if err := publishFixedRuntimeFile(path, []byte(bootHoldReleaseData)); err == nil ||
		err.Error() != "SETUP_BOOT_HOLD_RELEASE_INVALID" {
		t.Fatalf("changed fixed state was accepted: %v", err)
	}
	missingParent := filepath.Join(root, "missing", "state")
	if err := publishFixedRuntimeFile(missingParent, []byte(bootHoldReadyData)); err == nil ||
		err.Error() != "SETUP_BOOT_HOLD_RELEASE_FAILED" {
		t.Fatalf("missing protected runtime parent was accepted: %v", err)
	}
}

func TestManagedDockerHoldRefusalMatrix(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *System)
	}{
		{name: "missing-marker", mutate: func(t *testing.T, s *System) {
			writeFixture(t, s.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
			writeFixture(t, s.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
		}},
		{name: "partial-fragments", mutate: func(t *testing.T, s *System) {
			if err := publishBootHoldMarker(s.Paths.BootHoldMarker); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, s.Paths.DockerHoldService, []byte(dockerServiceHoldDropInData), 0o644)
		}},
		{name: "changed-fragment", mutate: func(t *testing.T, s *System) {
			if err := publishBootHoldMarker(s.Paths.BootHoldMarker); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, s.Paths.DockerHoldService, []byte("[Unit]\n"), 0o644)
			writeFixture(t, s.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
		}},
		{name: "symlink-fragment", mutate: func(t *testing.T, s *System) {
			if err := publishBootHoldMarker(s.Paths.BootHoldMarker); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(t.TempDir(), "foreign")
			writeFixture(t, foreign, []byte(dockerSocketHoldDropInData), 0o644)
			if err := os.MkdirAll(filepath.Dir(s.Paths.DockerHoldService), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(foreign, s.Paths.DockerHoldService); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, s.Paths.DockerHoldSocket, []byte(dockerSocketHoldDropInData), 0o644)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootFixture(t)
			system, _ := managedBootSystem(t, fixture)
			test.mutate(t, system)
			if err := system.WaitDockerHold(context.Background()); err == nil ||
				err.Error() != "SETUP_DOCKER_HOLD_STATE_INVALID" {
				t.Fatalf("unsafe Docker hold state was accepted: %v", err)
			}
		})
	}
}

func waitForRuntimeState(t *testing.T, ctx context.Context, path, expected string, want bool) {
	t.Helper()
	for {
		present, err := protectedFixedRuntimeState(path, expected)
		if err == nil && present == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("runtime state %s did not reach %t: %v", path, want, err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func FuzzManagedGRUBParserNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"linux /boot/vmlinuz-test ro ipv6.disable=1",
		`linuxefi "/boot/vmlinuz-test" 'ipv6.disable=1'`,
		"linux /boot/vmlinuz-test ipv6.disable=0",
		"linux /boot/vmlinuz-test ipv6.disable=1 ipv6.disable=1",
		"linux /boot/vmlinuz-test trailing\\",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 128<<10 {
			t.Skip()
		}
		_, _ = grubWords(line)
		_ = verifyGeneratedGRUB([]byte(line+"\n"), true, "vmlinuz-test")
	})
}

func BenchmarkManagedGRUBGeneratedVerification(b *testing.B) {
	data := preparedGRUB()
	b.ReportAllocs()
	for b.Loop() {
		if err := verifyGeneratedGRUB(data, true, "vmlinuz-"+testKernelRelease); err != nil {
			b.Fatal(err)
		}
	}
}
