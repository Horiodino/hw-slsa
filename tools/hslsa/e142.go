package hslsa

// A reader for SEMI E142 substrate maps in XML, the wafer maps a sort house
// hands its customer. It reads the part of the format a sort map uses: the
// layout's dimensions, each wafer's id and lot, and one bin code map per
// wafer with its bin definitions. Element names are matched without their
// namespace, so a map written against any revision of the E142 schema reads
// the same.

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type e142MapData struct {
	Layouts []struct {
		ID        string `xml:"LayoutId,attr"`
		Dimension struct {
			X int `xml:"X,attr"`
			Y int `xml:"Y,attr"`
		} `xml:"Dimension"`
	} `xml:"Layouts>Layout"`
	Substrates []struct {
		Type  string `xml:"SubstrateType,attr"`
		ID    string `xml:"SubstrateId,attr"`
		LotID string `xml:"LotId"`
	} `xml:"Substrates>Substrate"`
	Maps []struct {
		Type     string `xml:"SubstrateType,attr"`
		ID       string `xml:"SubstrateId,attr"`
		Layout   string `xml:"LayoutSpecifier,attr"`
		Origin   string `xml:"OriginLocation,attr"`
		Overlays []struct {
			Name   string `xml:"MapName,attr"`
			BinMap *struct {
				BinType string `xml:"BinType,attr"`
				NullBin string `xml:"NullBin,attr"`
				Defs    []struct {
					Code    string `xml:"BinCode,attr"`
					Quality string `xml:"BinQuality,attr"`
				} `xml:"BinDefinitions>BinDefinition"`
				Rows []string `xml:"BinCode"`
			} `xml:"BinCodeMap"`
		} `xml:"Overlay"`
	} `xml:"SubstrateMaps>SubstrateMap"`
}

// WaferMap is one wafer's sort map: each die that has a bin, and whether
// that bin is a passing one.
type WaferMap struct {
	Wafer      string
	LotID      string
	Cols, Rows int
	Pass       map[[2]int64]bool // (x, y) -> passed
}

// binWidth is how many characters one die's bin code takes in a row.
var binWidth = map[string]int{"HexaDecimal": 2, "ASCII": 1}

// ReadE142 reads every wafer map in a SEMI E142 XML file.
func ReadE142(path string) ([]WaferMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc e142MapData
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	fail := func(format string, a ...any) error { return fmt.Errorf("%s: %s", path, fmt.Sprintf(format, a...)) }
	lots := map[string]string{}
	for _, s := range doc.Substrates {
		lots[s.ID] = strings.TrimSpace(s.LotID)
	}
	var out []WaferMap
	for _, m := range doc.Maps {
		if m.Type != "Wafer" {
			continue
		}
		layoutID := m.Layout[strings.LastIndex(m.Layout, "/")+1:]
		cols, rows := -1, -1
		for _, l := range doc.Layouts {
			if l.ID == layoutID {
				cols, rows = l.Dimension.X, l.Dimension.Y
			}
		}
		if cols <= 0 || rows <= 0 {
			return nil, fail("wafer %s: layout %q has no dimensions", m.ID, m.Layout)
		}
		var bins []int
		for i, o := range m.Overlays {
			if o.BinMap != nil {
				bins = append(bins, i)
			}
		}
		if len(bins) != 1 {
			return nil, fail("wafer %s: want one overlay with a bin code map, found %d", m.ID, len(bins))
		}
		bm := m.Overlays[bins[0]].BinMap
		width := binWidth[bm.BinType]
		if width == 0 {
			return nil, fail("wafer %s: BinType %q is not supported (HexaDecimal or ASCII)", m.ID, bm.BinType)
		}
		quality := map[string]string{}
		for _, d := range bm.Defs {
			quality[strings.ToUpper(d.Code)] = d.Quality
		}
		if len(bm.Rows) != rows {
			return nil, fail("wafer %s: %d rows of bin codes, layout has %d", m.ID, len(bm.Rows), rows)
		}
		w := WaferMap{Wafer: m.ID, LotID: lots[m.ID], Cols: cols, Rows: rows, Pass: map[[2]int64]bool{}}
		for r, row := range bm.Rows {
			row = strings.TrimSpace(row)
			if len(row) != cols*width {
				return nil, fail("wafer %s: row %d has %d characters, want %d", m.ID, r, len(row), cols*width)
			}
			y := int64(r)
			switch m.Origin {
			case "UpperLeft":
			case "LowerLeft":
				y = int64(rows - 1 - r)
			default:
				return nil, fail("wafer %s: OriginLocation %q is not supported (UpperLeft or LowerLeft)", m.ID, m.Origin)
			}
			for x := 0; x < cols; x++ {
				code := strings.ToUpper(row[x*width : (x+1)*width])
				if strings.EqualFold(code, bm.NullBin) {
					continue
				}
				q, ok := quality[code]
				if !ok {
					return nil, fail("wafer %s: die (%d,%d) has bin %s, which has no BinDefinition", m.ID, x, y, code)
				}
				w.Pass[[2]int64{int64(x), y}] = q == "Pass"
			}
		}
		out = append(out, w)
	}
	if len(out) == 0 {
		return nil, fail("no wafer maps")
	}
	return out, nil
}
