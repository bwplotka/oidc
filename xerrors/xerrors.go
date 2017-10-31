package xerrors

/*
 "xerrors" package allows to have combo error logic. If passed errors were actually nils, it will return no error as well
 for "ErrorOrNil" method.
*/

import (
	"errors"
	"sync"
)

type combo struct {
	errsMu sync.Mutex
	errs   []error
}

// New constructs new combo struct.
func New() *combo {
	return &combo{}
}

// Add adds error to combo only if it is non-nil.
func (e *combo) Add(err error) {
	if err == nil {
		return
	}

	e.errsMu.Lock()
	defer e.errsMu.Unlock()
	e.errs = append(e.errs, err)
}

// ErrorOrNil returns error or nil if there was nothing added (or nil were added).
func (e *combo) ErrorOrNil() error {
	e.errsMu.Lock()
	defer e.errsMu.Unlock()
	if len(e.errs) == 0 {
		return nil
	}

	var msg string
	for _, err := range e.errs {
		// TODO: Impelement more sophisticated delimiter.
		msg += err.Error() + " "
	}
	return errors.New(msg)
}
