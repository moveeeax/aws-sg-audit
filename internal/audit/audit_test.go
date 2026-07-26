package audit

import "testing"

func sg(id string, attached bool, ingress ...Perm) SecurityGroup {
	return SecurityGroup{ID: id, Name: id + "-name", Region: "us-east-1", Attached: attached, Ingress: ingress}
}

func tcp(from, to int, cidr ...string) Perm {
	return Perm{Proto: "tcp", FromPort: from, ToPort: to, CIDRs: cidr}
}

func find(fs []Finding, port int) *Finding {
	for i := range fs {
		if fs[i].Port == port {
			return &fs[i]
		}
	}
	return nil
}

func TestWorldOpenSSH(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", false, tcp(22, 22, "0.0.0.0/0"))}, Options{})
	if len(fs) != 1 || fs[0].Service != "SSH" || fs[0].Severity != High {
		t.Fatalf("want one SSH high finding, got %+v", fs)
	}
	if fs[0].CIDR != "0.0.0.0/0" {
		t.Errorf("cidr = %s", fs[0].CIDR)
	}
}

func TestPublicPortsIgnored(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", false, tcp(80, 80, "0.0.0.0/0"), tcp(443, 443, "0.0.0.0/0"))}, Options{})
	if len(fs) != 0 {
		t.Fatalf("public ports 80/443 should not be flagged, got %+v", fs)
	}
}

func TestNonWorldNotFlagged(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", false, tcp(22, 22, "10.0.0.0/8"))}, Options{})
	if len(fs) != 0 {
		t.Fatalf("restricted CIDR should not be flagged, got %+v", fs)
	}
}

func TestPortRangeExpands(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", false, tcp(20, 25, "0.0.0.0/0"))}, Options{})
	// 21 FTP, 22 SSH, 23 Telnet fall in [20,25]; 80/443 do not.
	if find(fs, 21) == nil || find(fs, 22) == nil || find(fs, 23) == nil {
		t.Fatalf("expected findings for 21/22/23, got %+v", fs)
	}
	if find(fs, 23).Severity != Critical {
		t.Errorf("Telnet should be critical, got %s", find(fs, 23).Severity)
	}
}

func TestAllTrafficIsCritical(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", false, Perm{Proto: "-1", CIDRs: []string{"0.0.0.0/0"}})}, Options{})
	if len(fs) != 1 || fs[0].Severity != Critical || fs[0].Service != "ALL PORTS" || fs[0].Port != -1 {
		t.Fatalf("want one critical ALL PORTS finding, got %+v", fs)
	}
}

func TestAttachedBumpsSeverity(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", true, tcp(22, 22, "0.0.0.0/0"))}, Options{})
	if fs[0].Severity != Critical {
		t.Errorf("attached SSH (base high) should bump to critical, got %s", fs[0].Severity)
	}
	if !fs[0].Attached {
		t.Error("finding should be marked attached")
	}
}

func TestIPv6WorldOpen(t *testing.T) {
	fs := Audit([]SecurityGroup{{ID: "sg-1", Region: "eu-west-1", Ingress: []Perm{
		{Proto: "tcp", FromPort: 3306, ToPort: 3306, CIDRv6: []string{"::/0"}}}}}, Options{})
	if len(fs) != 1 || fs[0].CIDR != "::/0" || fs[0].Service != "MySQL" {
		t.Fatalf("want MySQL ::/0 finding, got %+v", fs)
	}
}

func TestIgnoreTag(t *testing.T) {
	s := sg("sg-1", false, tcp(22, 22, "0.0.0.0/0"))
	s.Tags = map[string]string{"sg-audit-ignore": "true"}
	fs := Audit([]SecurityGroup{s}, Options{IgnoreTag: "sg-audit-ignore"})
	if len(fs) != 0 {
		t.Fatalf("ignore-tagged SG should be skipped, got %+v", fs)
	}
}

func TestCustomPublicPortAllowsCustom(t *testing.T) {
	fs := Audit([]SecurityGroup{sg("sg-1", false, tcp(6379, 6379, "0.0.0.0/0"))},
		Options{PublicPorts: map[int]bool{6379: true}})
	if len(fs) != 0 {
		t.Fatalf("6379 marked public should not flag, got %+v", fs)
	}
}

func TestOrderingBySeverity(t *testing.T) {
	fs := Audit([]SecurityGroup{
		sg("sg-b", false, tcp(21, 21, "0.0.0.0/0")), // FTP medium
		sg("sg-a", false, tcp(23, 23, "0.0.0.0/0")), // Telnet critical
	}, Options{})
	if fs[0].Severity != Critical {
		t.Errorf("critical should sort first, got %+v", fs)
	}
}
