//go:build !darwin && !linux

package sandbox

import "fmt"

// Available reports whether the platform sandbox can be applied.
func Available() bool { return false }

// Exec is unsupported on this platform.
func Exec(plan *Plan, argv []string) error {
	return fmt.Errorf("kernel sandbox is not supported on this platform (darwin Seatbelt and linux Landlock only)")
}

// GapNotes describes what this platform's sandbox cannot express.
func GapNotes(plan *Plan) []string {
	return []string{"no kernel sandbox on this platform — hook-layer enforcement only"}
}
