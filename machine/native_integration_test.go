package machine

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// Opt in on supported real hosts and CI runners. Raw native IDs and derived
// bindings must never appear in test logs or uploaded artifacts.
func TestNativeAcrossProcesses(t *testing.T) {
	if os.Getenv("LICENSEBOX_TEST_NATIVE") != "1" {
		t.Skip("set LICENSEBOX_TEST_NATIVE=1 to exercise the host identity")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate test executable")
	}
	probe := func(product string) Binding {
		t.Helper()
		cmd := exec.Command(executable, "-test.run=^TestNativeProbeProcess$")
		cmd.Env = append(os.Environ(), "LICENSEBOX_NATIVE_PROBE_PRODUCT="+product)
		output, err := cmd.Output()
		if err != nil {
			t.Fatal("native identity unavailable in a fresh process")
		}
		binding := Binding(strings.TrimSpace(string(output)))
		if !binding.Valid() {
			t.Fatal("native provider returned an invalid binding")
		}
		return binding
	}
	a := probe("licensebox-native-test-a")
	if a != probe("licensebox-native-test-a") {
		t.Fatal("native identity changed across processes")
	}
	if a == probe("licensebox-native-test-b") {
		t.Fatal("native identity was not scoped to the product")
	}
	switch runtime.GOOS {
	case "windows":
		if a.Source() != "windows-smbios" {
			t.Fatal("unexpected Windows identity provider")
		}
	case "darwin":
		if a.Source() != "macos-platform" {
			t.Fatal("unexpected macOS identity provider")
		}
	case "linux":
		if !strings.HasPrefix(a.Source(), "linux-") {
			t.Fatal("unexpected Linux identity provider")
		}
	}
}

func TestNativeProbeProcess(t *testing.T) {
	product := os.Getenv("LICENSEBOX_NATIVE_PROBE_PRODUCT")
	if product == "" {
		t.Skip("helper process")
	}
	binding, err := Native(product)
	if err != nil {
		os.Exit(1)
	}
	fmt.Print(binding)
	os.Exit(0)
}
