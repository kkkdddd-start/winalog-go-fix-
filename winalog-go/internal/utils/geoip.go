package utils

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

type GeoIP struct {
	mu        sync.RWMutex
	countryDB map[string]*CountryEntry
	cityDB    map[string]*CityEntry
	isLoaded  bool
	dbPath    string
}

type CountryEntry struct {
	CountryCode string
	CountryName string
	Continent   string
	Region      string
}

type CityEntry struct {
	CountryCode string
	CountryName string
	City        string
	Region      string
	PostalCode  string
	Latitude    float64
	Longitude   float64
	Timezone    string
}

type GeoIPResult struct {
	IP           string
	CountryCode  string
	CountryName  string
	City         string
	Region       string
	Latitude     float64
	Longitude    float64
	Timezone     string
	Organization string
	ISP          string
	ASNumber     string
}

var defaultGeoIP *GeoIP
var geoIPOnce sync.Once

func GetGeoIP() *GeoIP {
	geoIPOnce.Do(func() {
		defaultGeoIP = NewGeoIP("")
	})
	return defaultGeoIP
}

func NewGeoIP(dbPath string) *GeoIP {
	return &GeoIP{
		countryDB: make(map[string]*CountryEntry),
		cityDB:    make(map[string]*CityEntry),
		isLoaded:  false,
		dbPath:    dbPath,
	}
}

func (g *GeoIP) Load(dbPath string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if dbPath == "" {
		g.isLoaded = false
		return nil
	}

	g.dbPath = dbPath
	g.isLoaded = false
	return nil
}

func (g *GeoIP) IsLoaded() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.isLoaded
}

func (g *GeoIP) LookupCountry(ip string) (*CountryEntry, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.isLoaded {
		return nil, fmt.Errorf("GeoIP database not loaded")
	}

	entry, ok := g.countryDB[ip]
	if !ok {
		return nil, fmt.Errorf("IP not found: %s", ip)
	}

	return entry, nil
}

func (g *GeoIP) LookupCity(ip string) (*CityEntry, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.isLoaded {
		return nil, fmt.Errorf("GeoIP database not loaded")
	}

	entry, ok := g.cityDB[ip]
	if !ok {
		return nil, fmt.Errorf("IP not found: %s", ip)
	}

	return entry, nil
}

func (g *GeoIP) Lookup(ip string) *GeoIPResult {
	result := &GeoIPResult{
		IP: ip,
	}

	if country, err := g.LookupCountry(ip); err == nil {
		result.CountryCode = country.CountryCode
		result.CountryName = country.CountryName
	}

	if city, err := g.LookupCity(ip); err == nil {
		result.City = city.City
		result.Region = city.Region
		result.Latitude = city.Latitude
		result.Longitude = city.Longitude
		result.Timezone = city.Timezone
	}

	return result
}

func (g *GeoIP) LookupDomain(domain string) (*GeoIPResult, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for domain: %s", domain)
	}

	return g.Lookup(ips[0].String()), nil
}

func (g *GeoIP) LoadFromCSV(r io.Reader, dbType string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	reader := csv.NewReader(r)

	if dbType == "country" {
		g.countryDB = make(map[string]*CountryEntry)
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}
			if len(record) < 4 {
				continue
			}
			g.countryDB[record[0]] = &CountryEntry{
				CountryCode: record[1],
				CountryName: record[2],
				Continent:   record[3],
				Region:      "",
			}
		}
	} else if dbType == "city" {
		g.cityDB = make(map[string]*CityEntry)
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}
			if len(record) < 10 {
				continue
			}
			g.cityDB[record[0]] = &CityEntry{
				CountryCode: record[1],
				CountryName: record[2],
				City:        record[3],
				Region:      record[4],
				PostalCode:  record[5],
				Timezone:    record[6],
			}
		}
	}

	g.isLoaded = true
	return nil
}

func LoadGeoIPFromFile(dbPath string) (*GeoIP, error) {
	g := NewGeoIP(dbPath)

	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoIP file: %w", err)
	}
	defer file.Close()

	if strings.HasSuffix(dbPath, ".csv") {
		err = g.LoadFromCSV(file, "city")
	} else {
		err = fmt.Errorf("unsupported file format")
	}

	if err != nil {
		return nil, err
	}

	return g, nil
}

func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, block := range privateBlocks {
		_, network, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func GetIPType(ip string) string {
	if IsPrivateIP(ip) {
		return "private"
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "unknown"
	}

	if parsedIP.IsLoopback() {
		return "loopback"
	}

	if parsedIP.IsMulticast() {
		return "multicast"
	}

	if parsedIP.IsUnspecified() {
		return "unspecified"
	}

	return "public"
}

func ResolveHostname(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for hostname: %s", hostname)
	}

	return ips[0].String(), nil
}

func ReverseDNS(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", fmt.Errorf("failed to lookup reverse DNS: %w", err)
	}

	if len(names) == 0 {
		return "", nil
	}

	return strings.TrimSuffix(names[0], "."), nil
}
