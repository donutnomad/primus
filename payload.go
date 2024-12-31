package primus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/samber/lo"
	"io"
)

type Payload struct {
	parts []PayloadPart
	_size int
}

func (p *Payload) add(part *PayloadPart) {
	p._size += part.Size()
	p.parts = append(p.parts, *part)
}

func (p *Payload) addBs(typ PayloadType, data []byte) {
	p.add(NewPayloadPart(typ, data))
}

func (p *Payload) addInt(typ PayloadType, data int) {
	p.add(NewPayloadPartInt(typ, data))
}

func (p *Payload) getNumberOfParts() int {
	return len(p.parts)
}

func (p *Payload) getParts() []PayloadPart {
	return p.parts
}

func (p *Payload) find(typ PayloadType) *PayloadPart {
	item, ok := lo.Find(p.parts, func(item PayloadPart) bool {
		return item.typ == typ
	})
	if !ok {
		return nil
	}
	return &item
}

func (p *Payload) findData(typ PayloadType) []byte {
	item := p.find(typ)
	if item == nil {
		return nil
	}
	return item.data
}

func (p *Payload) size() int {
	return p._size
}

func (p *Payload) Bytes() []byte {
	var out = make([]byte, 0, p.size())
	for _, part := range p.parts {
		assert(part.Size()%4 == 0)
		out = append(out, part.Serialize()...)
	}
	return out
}

func (p *Payload) Deserialize(data []byte) error {
	buf := bytes.NewReader(data)
	for {
		var part = new(PayloadPart)
		if err := part.Deserialize(buf); err != nil {
			return err
		}
		p.add(part)
		if buf.Len() <= 0 {
			break
		}
	}
	return nil
}

type PayloadPart struct {
	typ  PayloadType
	data []byte
}

func NewPayloadPart(typ PayloadType, data []byte) *PayloadPart {
	return &PayloadPart{
		typ:  typ & 0xffff,
		data: data,
	}
}

func NewPayloadPartInt(typ PayloadType, data int) *PayloadPart {
	return NewPayloadPart(typ, LEUint32(data))
}

func (p *PayloadPart) Data() []byte {
	return p.data
}

func (p *PayloadPart) Size() int {
	return 4 + lo.Ternary(len(p.data) <= 65534, 0, 4) + len(p.data) + padding(len(p.data))
}

func (p *PayloadPart) GetUint32() (uint32, error) {
	if len(p.data) != 4 {
		return 0, fmt.Errorf("expected size 4, got %d", len(p.data))
	}
	return binary.LittleEndian.Uint32(p.data[0:4]), nil
}

func (p *PayloadPart) MustGetUint32() uint32 {
	v, err := p.GetUint32()
	if err != nil {
		panic(err)
	}
	return v
}

func (p *PayloadPart) Deserialize(buf io.Reader) error {
	var typ int16
	if err := binary.Read(buf, binary.LittleEndian, &typ); err != nil {
		return err
	}
	p.typ = PayloadType(typ)
	var length int16
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		return err
	}
	if length == -1 {
		var extendedLength int32
		if err := binary.Read(buf, binary.LittleEndian, &extendedLength); err != nil {
			return err
		}
		length = int16(extendedLength)
	}
	p.data = make([]byte, length)
	if _, err := buf.Read(p.data); err != nil {
		return err
	}
	pad := padding(int(length))
	if pad > 0 {
		paddingBytes := make([]byte, pad)
		if _, err := buf.Read(paddingBytes); err != nil {
			return err
		}
	}
	return nil
}

func (p *PayloadPart) Serialize() []byte {
	var buf = new(bytes.Buffer)
	writeBuf := func(data any) {
		err := binary.Write(buf, binary.LittleEndian, data)
		if err != nil {
			panic(err)
		}
	}
	writeBuf(int16(p.typ))
	if len(p.data) <= 65534 {
		writeBuf(int16(len(p.data)))
	} else {
		writeBuf(int16(-1))
		writeBuf(int32(len(p.data)))
	}
	writeBuf(p.data)
	for i := 0; i < padding(len(p.data)); i++ {
		writeBuf(byte(0))
	}
	return buf.Bytes()
}

func roundUpToAlignment(n int) int {
	n = n + 3
	return n - n%4
}

func padding(n int) int {
	return roundUpToAlignment(n) - n
}
