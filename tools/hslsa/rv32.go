package hslsa

// A small RV32I assembler for the virtual shuttle's test programs (shuttle.go).
// It knows the base integer instructions PicoRV32 runs in its default
// configuration and resolves labels in two passes, so the probe and final
// test programs can be written in Go and reviewed as code.

import "fmt"

type rvItem struct {
	label string                                                // a label, when enc is nil
	enc   func(pc uint32, at map[string]uint32) (uint32, error) // one instruction
}

// rvAsm collects a program.
type rvAsm struct{ items []rvItem }

func (a *rvAsm) Label(name string) { a.items = append(a.items, rvItem{label: name}) }

func (a *rvAsm) emit(f func(pc uint32, at map[string]uint32) (uint32, error)) {
	a.items = append(a.items, rvItem{enc: f})
}

func (a *rvAsm) fixed(w uint32) {
	a.emit(func(uint32, map[string]uint32) (uint32, error) { return w, nil })
}

func rvR(f7, rs2, rs1, f3, rd, op uint32) uint32 {
	return f7<<25 | rs2<<20 | rs1<<15 | f3<<12 | rd<<7 | op
}

func rvI(imm int32, rs1, f3, rd, op uint32) uint32 {
	return uint32(imm&0xfff)<<20 | rs1<<15 | f3<<12 | rd<<7 | op
}

func rvS(imm int32, rs2, rs1, f3 uint32) uint32 {
	u := uint32(imm & 0xfff)
	return (u>>5)<<25 | rs2<<20 | rs1<<15 | f3<<12 | (u&0x1f)<<7 | 0x23
}

func rvB(off int32, rs2, rs1, f3 uint32) uint32 {
	u := uint32(off)
	return (u>>12&1)<<31 | (u>>5&0x3f)<<25 | rs2<<20 | rs1<<15 | f3<<12 | (u>>1&0xf)<<8 | (u>>11&1)<<7 | 0x63
}

func rvJ(off int32, rd uint32) uint32 {
	u := uint32(off)
	return (u>>20&1)<<31 | (u>>1&0x3ff)<<21 | (u>>11&1)<<20 | (u>>12&0xff)<<12 | rd<<7 | 0x6f
}

func checkImm(v int32, bits uint) error {
	lim := int32(1) << (bits - 1)
	if v < -lim || v >= lim {
		return fmt.Errorf("immediate %d does not fit in %d bits", v, bits)
	}
	return nil
}

// R-type: add sub sll slt sltu xor srl sra or and.
var rvROps = map[string][2]uint32{
	"add": {0, 0}, "sub": {0x20, 0}, "sll": {0, 1}, "slt": {0, 2}, "sltu": {0, 3},
	"xor": {0, 4}, "srl": {0, 5}, "sra": {0x20, 5}, "or": {0, 6}, "and": {0, 7},
}

func (a *rvAsm) R(op string, rd, rs1, rs2 uint32) {
	f := rvROps[op]
	a.fixed(rvR(f[0], rs2, rs1, f[1], rd, 0x33))
}

// I-type ALU: addi slti sltiu xori ori andi, and the shifts slli srli srai.
var rvIOps = map[string]uint32{"addi": 0, "slti": 2, "sltiu": 3, "xori": 4, "ori": 6, "andi": 7}

func (a *rvAsm) I(op string, rd, rs1 uint32, imm int32) {
	switch op {
	case "slli":
		a.fixed(rvR(0, uint32(imm&31), rs1, 1, rd, 0x13))
	case "srli":
		a.fixed(rvR(0, uint32(imm&31), rs1, 5, rd, 0x13))
	case "srai":
		a.fixed(rvR(0x20, uint32(imm&31), rs1, 5, rd, 0x13))
	default:
		f3 := rvIOps[op]
		a.emit(func(uint32, map[string]uint32) (uint32, error) {
			return rvI(imm, rs1, f3, rd, 0x13), checkImm(imm, 12)
		})
	}
}

// Loads lb lh lw lbu lhu and stores sb sh sw.
var rvLoads = map[string]uint32{"lb": 0, "lh": 1, "lw": 2, "lbu": 4, "lhu": 5}
var rvStores = map[string]uint32{"sb": 0, "sh": 1, "sw": 2}

func (a *rvAsm) Load(op string, rd, rs1 uint32, off int32) {
	a.emit(func(uint32, map[string]uint32) (uint32, error) {
		return rvI(off, rs1, rvLoads[op], rd, 0x03), checkImm(off, 12)
	})
}

func (a *rvAsm) Store(op string, rs2, rs1 uint32, off int32) {
	a.emit(func(uint32, map[string]uint32) (uint32, error) {
		return rvS(off, rs2, rs1, rvStores[op]), checkImm(off, 12)
	})
}

// Branches beq bne blt bge bltu bgeu to a label.
var rvBranches = map[string]uint32{"beq": 0, "bne": 1, "blt": 4, "bge": 5, "bltu": 6, "bgeu": 7}

func (a *rvAsm) Branch(op string, rs1, rs2 uint32, label string) {
	a.emit(func(pc uint32, at map[string]uint32) (uint32, error) {
		t, ok := at[label]
		if !ok {
			return 0, fmt.Errorf("no label %s", label)
		}
		off := int32(t - pc)
		return rvB(off, rs2, rs1, rvBranches[op]), checkImm(off, 13)
	})
}

// Jal jumps to a label, saving the return address in rd.
func (a *rvAsm) Jal(rd uint32, label string) {
	a.emit(func(pc uint32, at map[string]uint32) (uint32, error) {
		t, ok := at[label]
		if !ok {
			return 0, fmt.Errorf("no label %s", label)
		}
		off := int32(t - pc)
		return rvJ(off, rd), checkImm(off, 21)
	})
}

func (a *rvAsm) Jalr(rd, rs1 uint32, off int32) { a.fixed(rvI(off, rs1, 0, rd, 0x67)) }

func (a *rvAsm) Lui(rd, imm20 uint32) { a.fixed(imm20<<12 | rd<<7 | 0x37) }

func (a *rvAsm) Auipc(rd, imm20 uint32) { a.fixed(imm20<<12 | rd<<7 | 0x17) }

// Li loads any 32-bit constant with lui and addi.
func (a *rvAsm) Li(rd, v uint32) {
	lo := int32(v<<20) >> 20
	hi := (v - uint32(lo)) >> 12
	a.Lui(rd, hi&0xfffff)
	a.I("addi", rd, rd, lo)
}

// Words resolves the labels and returns the program as 32-bit words from address 0.
func (a *rvAsm) Words() ([]uint32, error) {
	at := map[string]uint32{}
	pc := uint32(0)
	for _, it := range a.items {
		if it.enc == nil {
			if _, dup := at[it.label]; dup {
				return nil, fmt.Errorf("label %s defined twice", it.label)
			}
			at[it.label] = pc
			continue
		}
		pc += 4
	}
	var out []uint32
	pc = 0
	for _, it := range a.items {
		if it.enc == nil {
			continue
		}
		w, err := it.enc(pc, at)
		if err != nil {
			return nil, fmt.Errorf("at 0x%x: %w", pc, err)
		}
		out = append(out, w)
		pc += 4
	}
	return out, nil
}
