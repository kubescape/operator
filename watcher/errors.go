package watcher

import (
	"errors"
)

var (
	errInvalidImageID = errors.New("input is not valid Image ID")

	ErrMissingInstanceIDAnnotation = errors.New("Object is missing Instance ID annotation")
)
