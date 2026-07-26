// Package audit flags security groups that expose sensitive ports to the world.
package audit

import "sort"

// Perm is one ingress rule, provider-agnostic so the audit is testable without AWS.
type Perm struct {
	Proto    string // "tcp", "udp", "icmp", or "-1" for all traffic
	FromPort int    // inclusive; ignored when Proto == "-1"
	ToPort   int    // inclusive
	CIDRs    []string
	CIDRv6   []string
}

// SecurityGroup is the normalized shape the audit consumes.
type SecurityGroup struct {
	ID       string
	Name     string
	Region   string
	VpcID    string
	Tags     map[string]string
	Ingress  []Perm
	Attached bool
}

// Severity levels, ordered.
const (
	Medium   = "medium"
	High     = "high"
	Critical = "critical"
)

var sevRank = map[string]int{Medium: 1, High: 2, Critical: 3}

// rule describes a sensitive port.
type rule struct {
	name     string
	severity string
}

// sensitivePorts maps a TCP port to the service it exposes and its base severity.
var sensitivePorts = map[int]rule{
	21:    {"FTP", Medium},
	22:    {"SSH", High},
	23:    {"Telnet", Critical},
	135:   {"MSRPC", Medium},
	445:   {"SMB", Critical},
	1433:  {"MSSQL", High},
	2379:  {"etcd", High},
	3306:  {"MySQL", High},
	3389:  {"RDP", High},
	5432:  {"PostgreSQL", High},
	5601:  {"Kibana", Medium},
	6379:  {"Redis", High},
	9200:  {"Elasticsearch", High},
	11211: {"Memcached", High},
	27017: {"MongoDB", High},
}

// Finding is one exposed sensitive port on one security group.
type Finding struct {
	SGID     string `json:"sg_id"`
	SGName   string `json:"sg_name"`
	Region   string `json:"region"`
	Proto    string `json:"proto"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	CIDR     string `json:"cidr"`
	Severity string `json:"severity"`
	Attached bool   `json:"attached"`
}

// Options tunes the audit.
type Options struct {
	// PublicPorts are intentionally world-open (e.g. 80, 443) and never flagged.
	PublicPorts map[int]bool
	// IgnoreTag, when set, skips any SG carrying that tag key.
	IgnoreTag string
}

// DefaultPublicPorts is the built-in allowlist for intended public ports.
func DefaultPublicPorts() map[int]bool { return map[int]bool{80: true, 443: true} }

// Audit returns findings ordered by severity (desc) then SG id and port.
func Audit(sgs []SecurityGroup, opts Options) []Finding {
	if opts.PublicPorts == nil {
		opts.PublicPorts = DefaultPublicPorts()
	}
	var out []Finding
	for _, sg := range sgs {
		if opts.IgnoreTag != "" {
			if _, ok := sg.Tags[opts.IgnoreTag]; ok {
				continue
			}
		}
		for _, p := range sg.Ingress {
			for _, cidr := range worldCIDRs(p) {
				out = append(out, findingsForPerm(sg, p, cidr, opts)...)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank[out[i].Severity] != sevRank[out[j].Severity] {
			return sevRank[out[i].Severity] > sevRank[out[j].Severity]
		}
		if out[i].SGID != out[j].SGID {
			return out[i].SGID < out[j].SGID
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// worldCIDRs returns the world-open CIDRs (v4 0.0.0.0/0, v6 ::/0) present in a perm.
func worldCIDRs(p Perm) []string {
	var w []string
	for _, c := range p.CIDRs {
		if c == "0.0.0.0/0" {
			w = append(w, c)
		}
	}
	for _, c := range p.CIDRv6 {
		if c == "::/0" {
			w = append(w, c)
		}
	}
	return w
}

func findingsForPerm(sg SecurityGroup, p Perm, cidr string, opts Options) []Finding {
	// Only TCP and all-traffic carry the sensitive TCP services.
	if p.Proto != "tcp" && p.Proto != "-1" {
		return nil
	}
	mk := func(port int, service, sev string) Finding {
		if sg.Attached {
			sev = bump(sev)
		}
		return Finding{
			SGID: sg.ID, SGName: sg.Name, Region: sg.Region,
			Proto: protoLabel(p.Proto), Port: port, Service: service,
			CIDR: cidr, Severity: sev, Attached: sg.Attached,
		}
	}

	// All traffic / full port range open is the worst case.
	if p.Proto == "-1" || (p.FromPort <= 0 && p.ToPort >= 65535) {
		return []Finding{mk(-1, "ALL PORTS", Critical)}
	}

	var out []Finding
	for port, r := range sensitivePorts {
		if port < p.FromPort || port > p.ToPort {
			continue
		}
		if opts.PublicPorts[port] {
			continue
		}
		out = append(out, mk(port, r.name, r.severity))
	}
	return out
}

func bump(sev string) string {
	switch sev {
	case Medium:
		return High
	case High:
		return Critical
	default:
		return Critical
	}
}

func protoLabel(p string) string {
	if p == "-1" {
		return "all"
	}
	return p
}
