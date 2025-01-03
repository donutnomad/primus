package primus

import (
	"errors"
	"github.com/samber/lo"
	"math"
)

type AccessToken struct {
	Name        string         `json:"name"`
	DelayMs     int64          `json:"delay_ms"`      // milliseconds
	TimeLimitMs int64          `json:"time_limit_ms"` // milliseconds
	Groups      []*AccessGroup `json:"groups"`
}

func (t *AccessToken) Serialize(p *Payload) {
	if namingSupport && len(t.Name) > 0 {
		p.addBs(LABEL_UTF8STRING, []byte(t.Name))
	}

	var doMinutes = true
	if supportsSeconds {
		delayS := t.DelayMs / 1000
		limitS := t.TimeLimitMs / 1000
		if (delayS%60 != 0 || limitS%60 != 0) && delayS < math.MaxInt32 && limitS < math.MaxInt32 {
			p.addInt(TIME_SECOND, int(delayS))
			p.addInt(TIME_SECOND, int(limitS))
			doMinutes = false
		}
	}

	if doMinutes {
		p.addInt(TIME_MINUTE, int(t.DelayMs/1000/60))
		p.addInt(TIME_MINUTE, int(t.TimeLimitMs/1000/60))
	}

	SerializeAllTag(GROUP_COUNT, t.Groups, p)
}

func (t *AccessToken) Deserialize(it *IterPart) (err error) {
	defer RecoverErr(&err)
	one := it.MustNext()

	if one.typ == LABEL_UTF8STRING {
		t.Name = string(one.Data())
		one = it.MustNext()
	}

	if one.typ == TIME_SECOND {
		t.DelayMs = int64(lo.Must1(one.GetUint32())) * 1000
		one = it.MustNext2(TIME_SECOND)
		t.TimeLimitMs = int64(lo.Must1(one.GetUint32())) * 1000
	} else if one.typ == TIME_MINUTE {
		t.DelayMs = int64(lo.Must1(one.GetUint32())) * 1000 * 60
		one = it.MustNext2(TIME_MINUTE)
		t.TimeLimitMs = int64(lo.Must1(one.GetUint32())) * 1000 * 60
	} else {
		return errors.New("invalid payload type, required TIME_SECOND or TIME_MINUTE")
	}

	one = it.MustNext2(GROUP_COUNT)
	count := int(lo.Must1(one.GetUint32()))
	t.Groups = make([]*AccessGroup, count)

	for i := 0; i < count; i++ {
		item := new(AccessGroup)
		err := item.Deserialize(it)
		if err != nil {
			return err
		}
		t.Groups[i] = item
	}
	return nil
}
