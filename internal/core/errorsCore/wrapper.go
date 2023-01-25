package errorsCore

import "fmt"

func WrapError(s string, e error) error {
	return fmt.Errorf("%s: %w", s, e)
}
