//go:build !darwin

package shell

func openAirDrop(path string) bool {
	return false
}
