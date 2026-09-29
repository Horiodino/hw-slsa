package hslsa

// A writer for STDF V4 records: the virtual shuttle's testers write their
// results with it (shuttle.go), and the tests write the sample exports.

import (
	"bytes"
	"encoding/binary"
)

// stdfFile writes STDF V4 records, little-endian (FAR CPU_TYPE 2) unless
// big is set (CPU_TYPE 1).
type stdfFile struct {
	bytes.Buffer
	big bool
}

func (f *stdfFile) order() binary.ByteOrder {
	if f.big {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func noErr(err error) {
	if err != nil {
		panic(err)
	}
}

func (f *stdfFile) rec(typ, sub byte, fields ...any) {
	var body bytes.Buffer
	for _, v := range fields {
		switch x := v.(type) {
		case string:
			body.WriteByte(byte(len(x)))
			body.WriteString(x)
		default:
			noErr(binary.Write(&body, f.order(), x))
		}
	}
	noErr(binary.Write(&f.Buffer, f.order(), uint16(body.Len())))
	f.WriteByte(typ)
	f.WriteByte(sub)
	f.Write(body.Bytes())
}
