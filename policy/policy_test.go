package policy

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

func number(v float64) *float64 { return &v }

func TestLocationRules(t *testing.T) {
	city := Location{Country: "AT", City: "Vienna", Latitude: number(48.2082), Longitude: number(16.3738)}
	for _, tt := range []struct {
		name string
		p    Locations
		l    Location
		want error
	}{
		{"unrestricted offline metadata", Locations{}, Location{}, nil},
		{"allowed country", Locations{Allow: []Area{{Country: "AT"}}}, city, nil},
		{"outside country", Locations{Allow: []Area{{Country: "DE"}}}, city, ErrDenied},
		{"block overrides allow", Locations{Allow: []Area{{Country: "AT"}}, Block: []Area{{Country: "AT", City: "Vienna"}}}, city, ErrDenied},
		{"city insensitive", Locations{Allow: []Area{{Country: "AT", City: "vienna"}}}, city, nil},
		{"city country disambiguation", Locations{Allow: []Area{{Country: "US", City: "Vienna"}}}, city, ErrDenied},
		{"nearby city radius", Locations{Allow: []Area{{Latitude: number(48.2082), Longitude: number(16.3738), RadiusKM: 80}}}, Location{Latitude: number(48.3069), Longitude: number(14.2858)}, ErrDenied},
		{"inside radius", Locations{Allow: []Area{{Latitude: number(48.2082), Longitude: number(16.3738), RadiusKM: 80}}}, Location{Latitude: number(48.1), Longitude: number(16.4)}, nil},
		{"unknown allowed country", Locations{Allow: []Area{{Country: "AT"}}}, Location{}, ErrUnknown},
		{"unknown blocked city", Locations{Block: []Area{{Country: "AT", City: "Vienna"}}}, Location{Country: "AT"}, ErrUnknown},
		{"different blocked country needs no city", Locations{Block: []Area{{Country: "DE", City: "Berlin"}}}, Location{Country: "AT"}, nil},
		{"allow union", Locations{Allow: []Area{{Country: "DE", City: "Berlin"}, {Country: "AT"}}}, city, nil},
		{"invalid coordinates", Locations{Allow: []Area{{Latitude: number(0), Longitude: number(0), RadiusKM: 5}}}, Location{Latitude: number(math.NaN()), Longitude: number(0)}, ErrUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Check(tt.l); !errors.Is(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestAreaTextAndValidation(t *testing.T) {
	text := "at; AT | Vienna; 48.2082,16.3738 | 80; AT | 0,0 | 5"
	areas, err := ParseAreas(text)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseAreas(FormatAreas(areas))
	if err != nil || !reflect.DeepEqual(areas, again) {
		t.Fatalf("roundtrip %v %v", again, err)
	}
	for _, text := range []string{"", "AT", "AT | Vienna"} {
		if _, err := ParseAreas(text); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"Austria", "Vienna", "AT | 0,0 | -1", "91,0 | 10", "0,181 | 10", "0,0 | NaN", "AT | Berlin | 5", "AT | Vienna | bad | format"} {
		if _, err := ParseAreas(text); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}
