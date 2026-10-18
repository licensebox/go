// Package policy describes licensing rules shared by the admin API and server.
// Products enforce them centrally; applications only handle the result.
package policy

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
)

// Area is a country, a city within a country, or a radius in kilometres.
// Radius rules require both coordinates. Country may further constrain a radius.
type Area struct {
	Country   string   `json:"country,omitempty"`
	City      string   `json:"city,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
	RadiusKM  float64  `json:"radius_km,omitempty"`
}

// Locations permits any Allow area (or everywhere if empty), except any Block
// area. Missing location information required to decide a rule fails closed.
type Locations struct {
	Allow []Area `json:"allow,omitempty"`
	Block []Area `json:"block,omitempty"`
}

// Location comes from a trusted server-side geolocation provider, never client
// JSON or arbitrary request headers. IP locations are approximate, not GPS.
type Location struct {
	Country   string   `json:"country,omitempty"`
	City      string   `json:"city,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}

var (
	ErrDenied  = errors.New("this location is outside the product's permitted areas")
	ErrUnknown = errors.New("the connection's location cannot be verified; contact the product administrator")
)

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Validate checks and normalizes the configured areas.
func (p *Locations) Validate() error {
	if len(p.Allow)+len(p.Block) > 100 {
		return errors.New("use at most 100 location areas")
	}
	for _, areas := range [][]Area{p.Allow, p.Block} {
		for i := range areas {
			a := &areas[i]
			a.Country = strings.ToUpper(strings.TrimSpace(a.Country))
			a.City = strings.TrimSpace(a.City)
			if a.Country != "" && (len(a.Country) != 2 || a.Country[0] < 'A' || a.Country[0] > 'Z' || a.Country[1] < 'A' || a.Country[1] > 'Z' || a.Country == "XX") {
				return fmt.Errorf("country %q: use a two-letter country code", a.Country)
			}
			if len(a.City) > 100 || strings.ContainsFunc(a.City, unicode.IsControl) {
				return errors.New("a city must be one line of at most 100 characters")
			}
			radius := a.Latitude != nil || a.Longitude != nil || a.RadiusKM != 0
			if radius {
				if a.Latitude == nil || a.Longitude == nil || !finite(*a.Latitude) || !finite(*a.Longitude) || math.Abs(*a.Latitude) > 90 || math.Abs(*a.Longitude) > 180 || !finite(a.RadiusKM) || a.RadiusKM <= 0 || a.RadiusKM > 20040 || a.City != "" {
					return errors.New("a radius needs valid latitude, longitude and radius_km (0 to 20040), without a city")
				}
			} else if a.Country == "" {
				return errors.New("an area needs a country, or coordinates and radius_km")
			}
		}
	}
	return nil
}

func (a Area) match(l Location) (bool, bool) {
	if a.Country != "" {
		if l.Country == "" || l.Country == "XX" || l.Country == "T1" {
			return false, false
		}
		if !strings.EqualFold(a.Country, l.Country) {
			return false, true
		}
	}
	if a.City != "" {
		if l.City == "" {
			return false, false
		}
		return strings.EqualFold(a.City, l.City), true
	}
	if a.Latitude != nil {
		if l.Latitude == nil || l.Longitude == nil || !finite(*l.Latitude) || !finite(*l.Longitude) || math.Abs(*l.Latitude) > 90 || math.Abs(*l.Longitude) > 180 {
			return false, false
		}
		rad := math.Pi / 180
		dlat, dlon := (*l.Latitude-*a.Latitude)*rad, (*l.Longitude-*a.Longitude)*rad
		h := math.Pow(math.Sin(dlat/2), 2) + math.Cos(*a.Latitude*rad)*math.Cos(*l.Latitude*rad)*math.Pow(math.Sin(dlon/2), 2)
		distance := 6371.0088 * 2 * math.Asin(math.Sqrt(min(1, max(0, h))))
		return distance <= a.RadiusKM, true
	}
	return true, true
}

// Check applies block precedence and the union of allowed areas.
func (p Locations) Check(l Location) error {
	unknown := false
	for _, a := range p.Block {
		match, known := a.match(l)
		if match {
			return ErrDenied
		}
		unknown = unknown || !known
	}
	if unknown {
		return ErrUnknown
	}
	if len(p.Allow) == 0 {
		return nil
	}
	for _, a := range p.Allow {
		match, known := a.match(l)
		if match {
			return nil
		}
		unknown = unknown || !known
	}
	if unknown {
		return ErrUnknown
	}
	return ErrDenied
}
