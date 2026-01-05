package drain

import "io"

//go:generate go run github.com/HZ-PRE/XrarCore/common/errors/errorgen

type Drainer interface {
	AcknowledgeReceive(size int)
	Drain(reader io.Reader) error
}
