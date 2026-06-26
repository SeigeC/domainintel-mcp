package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer(
		"DomainIntel MCP",
		"0.1.0",
		server.WithToolCapabilities(false),
	)

	s.AddTool(mcp.NewTool("domain_whois",
		mcp.WithDescription("Look up domain WHOIS/RDAP information: registrar, registration/expiration dates, nameservers, and domain status"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("Domain name to look up, e.g. example.com"),
		),
	), whoisHandler)

	s.AddTool(mcp.NewTool("domain_dns",
		mcp.WithDescription("Query DNS records for a domain (A, NS, CNAME, MX, TXT, AAAA, CAA, SOA)"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("Domain name to query, e.g. example.com"),
		),
		mcp.WithString("type",
			mcp.Description("DNS record type: A, NS, CNAME, MX, TXT, AAAA, CAA, or SOA"),
			mcp.DefaultString("A"),
			mcp.Enum("A", "NS", "CNAME", "MX", "TXT", "AAAA", "CAA", "SOA"),
		),
	), dnsHandler)

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(io.Discard, "Server error: %v\n", err)
	}
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func whoisHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain, err := request.RequireString("domain")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := rdapLookup(domain)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("WHOIS lookup failed: %v", err)), nil
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(b)), nil
}

func dnsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domain, err := request.RequireString("domain")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	recordType, err := request.RequireString("type")
	if err != nil {
		recordType = "A"
	}
	result, err := dnsLookup(domain, recordType)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("DNS lookup failed: %v", err)), nil
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(b)), nil
}

type RDAPResponse struct {
	Domain           string           `json:"domain"`
	Status           []string         `json:"status"`
	RegistrationDate string           `json:"registration_date,omitempty"`
	ExpirationDate   string           `json:"expiration_date,omitempty"`
	LastChangedDate  string           `json:"last_changed_date,omitempty"`
	Nameservers      []RDAPNameserver `json:"nameservers"`
	Registrar        string           `json:"registrar,omitempty"`
}

type RDAPNameserver struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips,omitempty"`
}

type rdapRaw struct {
	LdName      string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
	Status      []string
	Events      []rdapRawEvent
	Nameservers []struct {
		LdName string `json:"ldhName"`
		IPs    []struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"ipAddresses"`
	}
	Entities []rdapEntity `json:"entities"`
}

type rdapRawEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles  []string `json:"roles"`
	VCard []any    `json:"vcardArray"`
}

func rdapLookup(domain string) (*RDAPResponse, error) {
	url := "https://rdap.org/domain/" + domain
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("domain not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var raw rdapRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	out := &RDAPResponse{
		Domain: strings.ToLower(domain),
		Status: raw.Status,
	}
	if raw.UnicodeName != "" {
		out.Domain = raw.UnicodeName
	}
	for _, e := range raw.Events {
		action := strings.ToLower(strings.TrimSpace(e.EventAction))
		switch action {
		case "registration":
			out.RegistrationDate = e.EventDate
		case "expiration":
			out.ExpirationDate = e.EventDate
		case "last changed":
			out.LastChangedDate = e.EventDate
		}
	}
	for _, ns := range raw.Nameservers {
		entry := RDAPNameserver{Name: ns.LdName}
		for _, ip := range ns.IPs {
			if ip.V4 != "" {
				entry.IPs = append(entry.IPs, ip.V4)
			}
			if ip.V6 != "" {
				entry.IPs = append(entry.IPs, ip.V6)
			}
		}
		out.Nameservers = append(out.Nameservers, entry)
	}
	for _, e := range raw.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				out.Registrar = extractVCardName(e.VCard)
			}
		}
	}
	return out, nil
}

func extractVCardName(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		if name == "fn" {
			val, _ := prop[3].(string)
			return val
		}
	}
	return ""
}

type DNSResponse struct {
	Domain  string      `json:"domain"`
	Type    string      `json:"type"`
	Records []DNSRecord `json:"records"`
}

type DNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

var recordTypeNum = map[string]int{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6,
	"MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257,
}

func dnsLookup(domain, recordType string) (*DNSResponse, error) {
	rt := strings.ToUpper(recordType)
	if _, ok := recordTypeNum[rt]; !ok {
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}

	url := "https://dns.google/resolve?name=" + domain + "&type=" + rt
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dns query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var doh dohResponse
	if err := json.Unmarshal(body, &doh); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if doh.Status == 3 {
		return &DNSResponse{Domain: domain, Type: rt, Records: []DNSRecord{}}, nil
	}
	if doh.Status != 0 {
		return nil, fmt.Errorf("dns rcode: %d", doh.Status)
	}

	out := &DNSResponse{Domain: domain, Type: rt}
	for _, a := range doh.Answer {
		t := typeName(a.Type)
		if t != rt {
			continue
		}
		out.Records = append(out.Records, DNSRecord{
			Name: a.Name,
			Type: t,
			TTL:  a.TTL,
			Data: a.Data,
		})
	}
	if out.Records == nil {
		out.Records = []DNSRecord{}
	}
	return out, nil
}

func typeName(num int) string {
	for name, n := range recordTypeNum {
		if n == num {
			return name
		}
	}
	return fmt.Sprintf("TYPE%d", num)
}
