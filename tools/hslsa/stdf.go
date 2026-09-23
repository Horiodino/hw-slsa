package hslsa

// A reader for STDF V4, the binary format testers write wafer sort and final
// test results in. It reads the records the MES and STDF adapter needs (FAR,
// MIR, WIR, WRR, PIR, PRR) and skips the rest by their length, so any
// tester's file parses whatever else it carries.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// STDF V4 record types (REC_TYP, REC_SUB) the adapter reads.
const (
	stdfFAR = 0<<8 | 10
	stdfMIR = 1<<8 | 10
	stdfWIR = 2<<8 | 10
	stdfWRR = 2<<8 | 20
	stdfPIR = 5<<8 | 10
	stdfPRR = 5<<8 | 20
)

// STDF is what the adapter reads from one STDF V4 file.
type STDF struct {
	LotID   string // MIR LOT_ID
	JobName string // MIR JOB_NAM, the test program
	JobRev  string // MIR JOB_REV, its revision
	Parts   []STDFPart
}

// STDFPart is one part's result (a PRR), with the wafer it was on when the
// file brackets it in WIR and WRR.
type STDFPart struct {
	Wafer   string // WIR WAFER_ID, or "" outside a wafer
	X, Y    int64  // X_COORD, Y_COORD; -32768 when not set
	PartID  string // PART_ID
	HardBin int64  // HARD_BIN
	Failed  bool   // PART_FLG bit 3
	Retest  bool   // PART_FLG bit 0 or 1: supersedes an earlier result for the same part
}

// stdfField reads the fields of one record in order. A record may end early,
// and fields past its end read as missing, as STDF allows.
type stdfField struct {
	b     []byte
	order binary.ByteOrder
	err   error
}

func (f *stdfField) take(n int) []byte {
	if f.err != nil || len(f.b) < n {
		if f.err == nil && len(f.b) > 0 {
			f.err = errors.New("field runs past the end of its record")
		}
		f.b = nil
		return nil
	}
	out := f.b[:n]
	f.b = f.b[n:]
	return out
}

func (f *stdfField) u1() int64 {
	if b := f.take(1); b != nil {
		return int64(b[0])
	}
	return 0
}

func (f *stdfField) u2() int64 {
	if b := f.take(2); b != nil {
		return int64(f.order.Uint16(b))
	}
	return 0
}

func (f *stdfField) i2() int64 {
	if b := f.take(2); b != nil {
		return int64(int16(f.order.Uint16(b)))
	}
	return -32768
}

func (f *stdfField) u4() int64 {
	if b := f.take(4); b != nil {
		return int64(f.order.Uint32(b))
	}
	return 0
}

// cn reads a string with a one-byte length.
func (f *stdfField) cn() string {
	n := f.take(1)
	if n == nil {
		return ""
	}
	return string(f.take(int(n[0])))
}

// ReadSTDF reads an STDF V4 file. The byte order comes from the FAR's
// CPU_TYPE: 1 is big-endian, 2 little-endian.
func ReadSTDF(path string) (*STDF, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out, err := parseSTDF(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func parseSTDF(data []byte) (*STDF, error) {
	if len(data) < 6 || data[2] != 0 || data[3] != 10 {
		return nil, errors.New("not an STDF file: it does not start with a FAR")
	}
	var order binary.ByteOrder
	switch data[4] {
	case 1:
		order = binary.BigEndian
	case 2:
		order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("FAR CPU_TYPE %d is not supported", data[4])
	}
	if data[5] != 4 {
		return nil, fmt.Errorf("STDF version %d, want 4", data[5])
	}
	out := &STDF{}
	wafer, inWafer, seenMIR := "", false, false
	for off := 0; off < len(data); {
		if len(data)-off < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(order.Uint16(data[off:]))
		typ := int(data[off+2])<<8 | int(data[off+3])
		if len(data)-off-4 < n {
			return nil, fmt.Errorf("record at byte %d runs past the end of the file", off)
		}
		f := &stdfField{b: data[off+4 : off+4+n], order: order}
		off += 4 + n
		switch typ {
		case stdfMIR:
			f.u4()    // SETUP_T
			f.u4()    // START_T
			f.u1()    // STAT_NUM
			f.take(6) // MODE_COD, RTST_COD, PROT_COD, BURN_TIM (U2), CMOD_COD
			out.LotID = f.cn()
			f.cn() // PART_TYP
			f.cn() // NODE_NAM
			f.cn() // TSTR_TYP
			out.JobName = f.cn()
			out.JobRev = f.cn()
			seenMIR = true
		case stdfWIR:
			f.u1() // HEAD_NUM
			f.u1() // SITE_GRP
			f.u4() // START_T
			if inWafer {
				return nil, fmt.Errorf("WIR for wafer %q before the WRR of wafer %q", wafer, wafer)
			}
			wafer, inWafer = f.cn(), true
			if wafer == "" {
				return nil, errors.New("WIR without a WAFER_ID")
			}
		case stdfWRR:
			if !inWafer {
				return nil, errors.New("WRR without a WIR")
			}
			inWafer = false
		case stdfPRR:
			f.u1() // HEAD_NUM
			f.u1() // SITE_NUM
			flg := f.u1()
			f.u2() // NUM_TEST
			p := STDFPart{HardBin: f.u2()}
			f.u2() // SOFT_BIN
			p.X, p.Y = f.i2(), f.i2()
			f.u4() // TEST_T
			p.PartID = f.cn()
			if flg&0x10 != 0 {
				return nil, fmt.Errorf("PRR for part %q has no pass/fail indication", p.PartID)
			}
			p.Failed, p.Retest = flg&0x08 != 0, flg&0x03 != 0
			if inWafer {
				p.Wafer = wafer
			}
			out.Parts = append(out.Parts, p)
		}
		if f.err != nil {
			return nil, fmt.Errorf("record %d.%d: %w", typ>>8, typ&0xff, f.err)
		}
	}
	if !seenMIR {
		return nil, errors.New("no MIR")
	}
	if inWafer {
		return nil, fmt.Errorf("wafer %q has no WRR", wafer)
	}
	return out, nil
}

// Results returns each part's final result, keyed by key(part). A part tested
// again replaces its earlier result only when its PRR says it is a retest;
// otherwise a second result for the same part is an error.
func (s *STDF) Results(key func(STDFPart) string) (map[string]STDFPart, []string, error) {
	out := map[string]STDFPart{}
	var order []string
	for _, p := range s.Parts {
		k := key(p)
		if _, seen := out[k]; seen {
			if !p.Retest {
				return nil, nil, fmt.Errorf("two results for part %s, and the second is not marked as a retest", k)
			}
		} else {
			order = append(order, k)
		}
		out[k] = p
	}
	return out, order, nil
}
