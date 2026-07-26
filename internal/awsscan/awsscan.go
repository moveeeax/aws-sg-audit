// Package awsscan collects security groups (and their attachment state) from AWS.
package awsscan

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/moveeeax/aws-sg-audit/internal/audit"
)

// Scanner returns normalized security groups for the given regions. It is the
// one seam the CLI depends on, so the audit runs against fixtures in tests.
type Scanner interface {
	Scan(ctx context.Context, regions []string) ([]audit.SecurityGroup, error)
}

// Client is the aws-sdk-go-v2 backed Scanner.
type Client struct {
	profile string
}

// New builds a Client using the given shared-config profile (empty = default chain).
func New(profile string) *Client { return &Client{profile: profile} }

// Scan enumerates security groups per region and marks each as attached when an
// ENI references it.
func (c *Client) Scan(ctx context.Context, regions []string) ([]audit.SecurityGroup, error) {
	var out []audit.SecurityGroup
	for _, region := range regions {
		opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
		if c.profile != "" {
			opts = append(opts, config.WithSharedConfigProfile(c.profile))
		}
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("load config for %s: %w", region, err)
		}
		api := ec2.NewFromConfig(cfg)

		attached, err := attachedGroups(ctx, api)
		if err != nil {
			return nil, fmt.Errorf("describe network interfaces in %s: %w", region, err)
		}

		p := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("describe security groups in %s: %w", region, err)
			}
			for _, g := range page.SecurityGroups {
				out = append(out, normalize(g, region, attached))
			}
		}
	}
	return out, nil
}

// attachedGroups returns the set of SG ids referenced by any network interface.
func attachedGroups(ctx context.Context, api *ec2.Client) (map[string]bool, error) {
	set := map[string]bool{}
	p := ec2.NewDescribeNetworkInterfacesPaginator(api, &ec2.DescribeNetworkInterfacesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, eni := range page.NetworkInterfaces {
			for _, g := range eni.Groups {
				set[aws.ToString(g.GroupId)] = true
			}
		}
	}
	return set, nil
}

func normalize(g ec2types.SecurityGroup, region string, attached map[string]bool) audit.SecurityGroup {
	tags := map[string]string{}
	for _, t := range g.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	sg := audit.SecurityGroup{
		ID:       aws.ToString(g.GroupId),
		Name:     aws.ToString(g.GroupName),
		Region:   region,
		VpcID:    aws.ToString(g.VpcId),
		Tags:     tags,
		Attached: attached[aws.ToString(g.GroupId)],
	}
	for _, perm := range g.IpPermissions {
		p := audit.Perm{
			Proto:    aws.ToString(perm.IpProtocol),
			FromPort: int(aws.ToInt32(perm.FromPort)),
			ToPort:   int(aws.ToInt32(perm.ToPort)),
		}
		for _, r := range perm.IpRanges {
			p.CIDRs = append(p.CIDRs, aws.ToString(r.CidrIp))
		}
		for _, r := range perm.Ipv6Ranges {
			p.CIDRv6 = append(p.CIDRv6, aws.ToString(r.CidrIpv6))
		}
		sg.Ingress = append(sg.Ingress, p)
	}
	return sg
}
