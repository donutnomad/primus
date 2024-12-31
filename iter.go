package primus

import (
	"errors"
	"fmt"
)

type IterPart struct {
	i     int
	items []PayloadPart
}

func NewIterPart(items []PayloadPart) *IterPart {
	return &IterPart{items: items}
}

func (p *IterPart) Next() (*PayloadPart, error) {
	if p.i >= len(p.items) {
		return nil, errors.New("parts is empty")
	}
	item := &p.items[p.i]
	p.i++
	return item, nil
}

func (p *IterPart) MustNext() *PayloadPart {
	next, err := p.Next()
	if err != nil {
		panic(err)
	}
	return next
}

func (p *IterPart) Next2(typ PayloadType) (*PayloadPart, error) {
	if p.i >= len(p.items) {
		return nil, errors.New("parts is empty")
	}
	item := &p.items[p.i]
	if item.typ != typ {
		return nil, fmt.Errorf("invalid payload type %d, required %d", item.typ, typ)
	}
	p.i++
	return item, nil
}

func (p *IterPart) MustNext2(typ PayloadType) *PayloadPart {
	next, err := p.Next2(typ)
	if err != nil {
		panic(err)
	}
	return next
}

func (p *IterPart) Panic(typ, required PayloadType) {
	panic(fmt.Errorf("invalid payload type %d, required %d", typ, required))
}
