package watcher

import (
	"errors"
)

var (
	errInvalidImageID = errors.New("input is not valid Image ID")

	ErrMissingInstanceIDAnnotation = errors.New("object is missing Instance ID annotation")
	ErrMissingWLIDAnnotation       = errors.New("object is missing the WLID annotation")
)
