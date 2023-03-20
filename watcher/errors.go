package watcher

import (
	"errors"
)

var (
	ErrUnsupportedEvent     = errors.New("Received an unsupported event type for processing")
	ErrUnsupportedObject    = errors.New("Unsupported object type")
	ErrUnknownImageID       = errors.New("Unknown image ID")
	ErrMissingWorkloadLabel = errors.New("Missing a necessary workload label")
)
