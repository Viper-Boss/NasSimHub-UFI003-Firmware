package voicemedia

import (
	"encoding/binary"
	"errors"
	"io"
)

// This is the fixed PCM boundary already used by the NAS media core.
// Opus encoding and WebRTC termination remain on the NAS.
const (
	FrameBytes   = 640 // 20 ms, 16 kHz, mono S16LE
	HeaderBytes  = 16
	TypePlayback = 1
	TypeCapture  = 2
	TypeClose    = 5
	TypeStart    = 6
	TypeStarted  = 7
	TypeError    = 8
)

var magic = [4]byte{'M', 'D', 'M', '2'}
var ErrFrame = errors.New("invalid media frame")

type Frame struct {
	Type     byte
	Sequence uint32
	Payload  []byte
}

func ReadFrame(reader io.Reader) (Frame, error) {
	var header [HeaderBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	if header[0] != magic[0] || header[1] != magic[1] ||
		header[2] != magic[2] || header[3] != magic[3] ||
		header[5] != 0 || header[6] != 0 || header[7] != 0 {
		return Frame{}, ErrFrame
	}
	length := binary.BigEndian.Uint32(header[12:16])
	if length > FrameBytes {
		return Frame{}, ErrFrame
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Type:     header[4],
		Sequence: binary.BigEndian.Uint32(header[8:12]),
		Payload:  payload,
	}, nil
}

func WriteFrame(writer io.Writer, frame Frame) error {
	if len(frame.Payload) > FrameBytes {
		return ErrFrame
	}
	var header [HeaderBytes]byte
	copy(header[:4], magic[:])
	header[4] = frame.Type
	binary.BigEndian.PutUint32(header[8:12], frame.Sequence)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(frame.Payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, frame.Payload)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
