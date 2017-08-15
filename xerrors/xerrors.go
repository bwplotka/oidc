package xerrors

import (
	"errors"
	"sync"
)

type x struct {
	errsMu sync.Mutex
	errs   []error
}

func New() *x {
	return &x{}
}

func (e *x) Add(err error) {
	if err == nil {
		return
	}

	e.errsMu.Lock()
	defer e.errsMu.Unlock()
	e.errs = append(e.errs, err)
}

func (e *x) ErrorOrNil() error {
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
