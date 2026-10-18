package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseAreas accepts one area per line (or separated by semicolons): AT,
// AT | Vienna, or 48.2082,16.3738 | 80. Radius rules may be prefixed AT |.
func ParseAreas(text string) ([]Area, error) {
	var out []Area
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == ';' }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		var a Area
		if len(parts) == 1 {
			a.Country = parts[0]
		} else {
			start := 0
			if len(parts) == 3 {
				a.Country = parts[0]
				start = 1
			}
			if len(parts)-start != 2 {
				return nil, fmt.Errorf("area %q: use country, country | city, or latitude,longitude | radius_km", line)
			}
			if coordinates := strings.Split(parts[start], ","); len(coordinates) == 2 {
				lat, e1 := strconv.ParseFloat(strings.TrimSpace(coordinates[0]), 64)
				lon, e2 := strconv.ParseFloat(strings.TrimSpace(coordinates[1]), 64)
				radius, e3 := strconv.ParseFloat(parts[start+1], 64)
				if e1 != nil || e2 != nil || e3 != nil {
					return nil, fmt.Errorf("area %q: invalid coordinates or radius", line)
				}
				a.Latitude, a.Longitude, a.RadiusKM = &lat, &lon, radius
			} else if start == 0 {
				a.Country, a.City = parts[0], parts[1]
			} else {
				return nil, fmt.Errorf("area %q: invalid radius", line)
			}
		}
		out = append(out, a)
	}
	p := Locations{Allow: out}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.Allow, nil
}

// FormatAreas is the editable representation accepted by ParseAreas.
func FormatAreas(areas []Area) string {
	lines := make([]string, 0, len(areas))
	for _, a := range areas {
		line := a.Country
		if a.Latitude != nil && a.Longitude != nil {
			line = fmt.Sprintf("%g,%g | %g", *a.Latitude, *a.Longitude, a.RadiusKM)
			if a.Country != "" {
				line = a.Country + " | " + line
			}
		} else if a.City != "" {
			line += " | " + a.City
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
