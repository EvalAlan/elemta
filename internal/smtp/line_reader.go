package smtp

import (
	"bufio"
	"errors"
)

var errSMTPLineTooLong = errors.New("SMTP line exceeds limit")

// readBoundedSMTPLine bounds allocation before a peer supplies a line terminator.
// A caller must close the connection after errSMTPLineTooLong because the
// unread remainder can no longer be interpreted as a new command or message.
func readBoundedSMTPLine(reader *bufio.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, min(limit, reader.Size()))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > limit-len(line) {
			return nil, errSMTPLineTooLong
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}
