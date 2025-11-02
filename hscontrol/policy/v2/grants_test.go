package v2

import (
	oldJson "encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

func TestNetCap_UnmarshalJSON(t *testing.T) {
	type fields struct {
		Protocol Protocol
		Port     []tailcfg.PortRange
	}
	tests := []struct {
		name    string
		args    []byte
		expect  fields
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "TCP single port",
			args: []byte(`"tcp:80"`),
			expect: fields{
				Protocol: ProtocolTCP,
				Port:     []tailcfg.PortRange{{First: 80, Last: 80}},
			},
			wantErr: assert.NoError,
		},
		{
			name: "UDP port range",
			args: []byte(`"udp:1000-2000"`),
			expect: fields{
				Protocol: ProtocolUDP,
				Port:     []tailcfg.PortRange{{First: 1000, Last: 2000}},
			},
			wantErr: assert.NoError,
		},
		{
			name: "Port wildcard",
			args: []byte(`"tcp:*"`),
			expect: fields{
				Protocol: ProtocolTCP,
				Port:     []tailcfg.PortRange{{First: 0, Last: 65535}},
			},
			wantErr: assert.NoError,
		},
		{
			name: "Only port",
			args: []byte(`"443"`),
			expect: fields{
				Protocol: "", // Empty protocol implies TCP UDP and ICMP
				Port:     []tailcfg.PortRange{{First: 443, Last: 443}},
			},
			wantErr: assert.NoError,
		},
		{
			name: "All port",
			args: []byte(`"*"`),
			expect: fields{
				Protocol: "", // Empty protocol implies TCP UDP and ICMP
				Port:     []tailcfg.PortRange{{First: 0, Last: 65535}},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip NetCap
			err := ip.UnmarshalJSON(tt.args)
			tt.wantErr(t, err)
			if err == nil {
				assert.Equalf(t, tt.expect.Protocol, ip.Protocol, "Protocol")
				assert.Equalf(t, tt.expect.Port, ip.Port, "Port")
			}
		})
	}
}

func TestAppCap_UnmarshalJSON(t *testing.T) {
	type fields struct {
		StrCap map[string][]tailcfg.RawMessage
	}
	tests := []struct {
		name    string
		args    []byte
		fields  fields
		wantErr assert.ErrorAssertionFunc
	}{
		{"Regular", []byte(`{"tailscale.com/cap/tailsql": [{"dataSrc": ["*"]}]}`), fields{
			StrCap: map[string][]tailcfg.RawMessage{"tailscale.com/cap/tailsql": {"{\"dataSrc\": [\"*\"]}"}},
		}, assert.NoError},
		{"Bad name", []byte(`{"tailsca!le.com/cap/tailsql": [{"dataSrc": ["*"]}]}`), fields{}, assert.Error},
		{"Mixed Value", []byte(`{"tailscale.com/cap/tailsql": [], ` +
			`"example.com/cap": [{"comp": true, "continue": ["abc", 123]}], ` +
			`"another.com/pac": ["json", true, false]}`),
			fields{
				StrCap: map[string][]tailcfg.RawMessage{
					"tailscale.com/cap/tailsql": {},
					"example.com/cap":           {`{"comp": true, "continue": ["abc", 123]}`},
					"another.com/pac":           {`"json"`, `true`, `false`},
				}}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var app AppCap
			err := app.UnmarshalJSON(tt.args)
			tt.wantErr(t, err)

			if err == nil {
				// Unmarshall them into interface{} for comparison
				var expectedCap = make(map[string][]interface{})
				var actualCapInterface = make(map[string][]interface{})

				for k, v := range tt.fields.StrCap {
					var vi []interface{}
					for _, rawMsg := range v {
						var item interface{}
						err := oldJson.Unmarshal([]byte(rawMsg), &item)
						assert.NoError(t, err)
						vi = append(vi, item)
					}
					assert.NoError(t, err)
					expectedCap[k] = vi
				}

				for k, v := range app {
					var vi []interface{}
					for _, rawMsg := range v {
						var item interface{}
						err := oldJson.Unmarshal([]byte(rawMsg), &item)
						assert.NoError(t, err)
						vi = append(vi, item)
					}
					assert.NoError(t, err)
					actualCapInterface[k] = vi
				}

				assert.Equalf(t, expectedCap, actualCapInterface, "AppCap")
			}
		})
	}
}

func TestGrants_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		args    []byte
		fields  Grant
		wantErr assert.ErrorAssertionFunc
	}{
		{"Grant", []byte(`{
			"src": ["group:eng"],
			"dst": ["tag:web-server"],
			"ip": ["80", "22"]
		  }`), Grant{
			Sources:      Aliases{gp("group:eng")},
			Destinations: Aliases{tp("tag:web-server")},
			IPs: []NetCap{{Protocol: "", Port: []tailcfg.PortRange{{First: 80, Last: 80}}},
				{Protocol: "", Port: []tailcfg.PortRange{{First: 22, Last: 22}}}},
		}, assert.NoError},
		{"Wildcard Grant", []byte(`{
			"src": ["*"],
			"dst": ["tag:web-server"],
			"ip": ["tcp:*", "*"]
		  }`), Grant{
			Sources:      Aliases{Wildcard},
			Destinations: Aliases{tp("tag:web-server")},
			IPs: []NetCap{{Protocol: ProtocolTCP, Port: []tailcfg.PortRange{{First: 0, Last: 65535}}},
				{Protocol: "", Port: []tailcfg.PortRange{{First: 0, Last: 65535}}}},
		}, assert.NoError},
		{"Grant Posture", []byte(`{
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"ip": ["*"],
			"srcPosture": ["posture:anyMac"]
    	}`), Grant{
			Sources:      Aliases{agp("autogroup:member")},
			Destinations: Aliases{agp("autogroup:self")},
			IPs:          []NetCap{{Protocol: "", Port: []tailcfg.PortRange{{First: 0, Last: 65535}}}},
			SrcPostures:  []SrcPosture{"posture:anyMac"},
		}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var g Grant
			err := g.UnmarshalJSON(tt.args)
			tt.wantErr(t, err)
			if err == nil {
				assert.Equalf(t, tt.fields, g, "Grant")
			}
		})
	}
}

func TestUnmarshalPolicyWithGrants(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Policy
		wantErr string
	}{
		{
			name: "basic-types",
			input: `
{
	"groups": {
		"group:example": [
			"testuser@headscale.net",
		],
		"group:other": [
			"otheruser@headscale.net",
		],
		"group:noat": [
			"noat@",
		],
	},

	"postures": {
		"posture:anyMac": [
			"node:os IN ['macos', 'linux']",
		],
	},

	"tagOwners": {
		"tag:user": ["testuser@headscale.net"],
		"tag:group": ["group:other"],
		"tag:userandgroup": ["testuser@headscale.net", "group:other"],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
		"outside": "192.168.0.0/16",
	},

	"grants": [
	    // All
		{
			"src": ["*"],
			"dst": ["*"],
			"ip": ["tcp:*"],
		},
		// Users
		{
			"src": ["testuser@headscale.net"],
			"dst": ["otheruser@headscale.net"],
			"ip": ["tcp:80"],
		},
		// Groups
		{
			"src": ["group:example"],
			"dst": ["group:other"],
			"ip": ["tcp:80"]
		},
		// Tailscale IP
		{
			"src": ["100.101.102.103"],
			"dst": ["100.101.102.104"],
			"ip": ["tcp:80"]
		},
		// Subnet
		{
			"src": ["10.0.0.0/8"],
			"dst": ["172.16.0.0/16"],
            "ip": ["udp:80"]
		},
		// Hosts
		{
			"src": ["subnet-1"],
			"dst": ["host-1"],
			"ip": ["tcp:80-88"]
		},
		// Tags
		{
			"src": ["tag:group"],
			"dst": ["tag:user"],
			"ip": ["tcp:80,443"]
		},
		// Autogroup
		{
			"src": ["tag:group"],
			"dst": ["autogroup:internet"],
			"ip": ["tcp:80"]
		},
		// Apps
		{
			"src": ["tag:group"],
			"dst": ["tag:user"],
			"app": {
				"tailscale.com/cap/tailsql": [{"dataSrc": ["*"]}]
			}
		},
		// Postures
		{
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"ip": ["*"],
			"srcPosture": ["posture:anyMac"]
		},
		// Via
		{
			"src": ["*"],
			"dst": ["*"],
			"ip": ["*"],
			"via": ["tag:userandgroup"]
		}
	],
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:example"): []Username{Username("testuser@headscale.net")},
					Group("group:other"):   []Username{Username("otheruser@headscale.net")},
					Group("group:noat"):    []Username{Username("noat@")},
				},
				TagOwners: TagOwners{
					Tag("tag:user"):         Owners{up("testuser@headscale.net")},
					Tag("tag:group"):        Owners{gp("group:other")},
					Tag("tag:userandgroup"): Owners{up("testuser@headscale.net"), gp("group:other")},
				},
				Hosts: Hosts{
					"host-1":   Prefix(mp("100.100.100.100/32")),
					"subnet-1": Prefix(mp("100.100.101.100/24")),
					"outside":  Prefix(mp("192.168.0.0/16")),
				},
				Postures: Postures{
					SrcPosture("posture:anyMac"): []string{
						"node:os IN ['macos', 'linux']",
					},
				},
				Grants: []Grant{
					{
						// All
						Sources: Aliases{
							Wildcard,
						},
						Destinations: Aliases{
							Wildcard,
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port:     []tailcfg.PortRange{{First: 0, Last: 65535}},
							},
						},
					},
					{
						// Users
						Sources: Aliases{
							ptr.To(Username("testuser@headscale.net")),
						},
						Destinations: Aliases{
							ptr.To(Username("otheruser@headscale.net")),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port:     []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						// Groups
						Sources: Aliases{
							gp("group:example"),
						},
						Destinations: Aliases{
							gp("group:other"),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port:     []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						// Tailscale IP
						Sources: Aliases{
							pp("100.101.102.103/32"),
						},
						Destinations: Aliases{
							pp("100.101.102.104/32"),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port:     []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						// Subnet
						Sources: Aliases{
							pp("10.0.0.0/8"),
						},
						Destinations: Aliases{
							pp("172.16.0.0/16"),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolUDP,
								Port:     []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						// Hosts
						Sources: Aliases{
							hp("subnet-1"),
						},
						Destinations: Aliases{
							hp("host-1"),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port:     []tailcfg.PortRange{{First: 80, Last: 88}},
							},
						},
					},
					{
						// Tags
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: Aliases{
							tp("tag:user"),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port: []tailcfg.PortRange{
									{First: 80, Last: 80},
									{First: 443, Last: 443},
								},
							},
						},
					},
					{
						// Autogroup
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: Aliases{
							agp("autogroup:internet"),
						},
						IPs: []NetCap{
							{
								Protocol: ProtocolTCP,
								Port:     []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						// Apps
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: Aliases{
							tp("tag:user"),
						},
						App: AppCap{
							"tailscale.com/cap/tailsql": {tailcfg.RawMessage(`{"dataSrc": ["*"]}`)},
						},
					},
					{
						// Postures
						Sources: Aliases{
							agp("autogroup:member"),
						},
						Destinations: Aliases{
							agp("autogroup:self"),
						},
						IPs: []NetCap{
							{
								Protocol: "",
								Port:     []tailcfg.PortRange{{First: 0, Last: 65535}},
							},
						},
						SrcPostures: []SrcPosture{"posture:anyMac"},
					},
					{
						// Via
						Sources: Aliases{
							Wildcard,
						},
						Destinations: Aliases{
							Wildcard,
						},
						IPs: []NetCap{
							{
								Protocol: "",
								Port:     []tailcfg.PortRange{{First: 0, Last: 65535}},
							},
						},
						Via: []Tag{
							Tag("tag:userandgroup"),
						},
					},
				},
			},
		},
		{
			name: "group-must-be-defined-grant-src",
			input: `
{
  "grants": [
    {
      "src": [
        "group:notdefined"
      ],
      "dst": [
        "autogroup:internet"
      ],
	  "ip": ["*"]
    }
  ]
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "group-must-be-defined-grant-dst",
			input: `
{
  "grants": [
    {
      "src": [
        "*"
      ],
      "dst": [
        "group:notdefined"
      ],
	  "ip": ["*"]
    }
  ]
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-grant-src",
			input: `
{
  "grants": [
    {
      "src": [
        "tag:notdefined"
      ],
      "dst": [
        "autogroup:internet"
      ],
	  "ip": ["*"]
    }
  ]
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-grant-dst",
			input: `
{
  "grants": [
    {
      "src": [
        "*"
      ],
      "dst": [
        "tag:notdefined"
      ],
	  "ip": ["*"]
    }
  ]
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "posture-must-be-defined-grant",
			input: `
{
  "grants": [
    {
      "src": [
        "*"
      ],
      "dst": [
        "*"
      ],
	  "ip": ["*"],
	  "srcPosture": ["posture:notdefined"]
    }
  ]
}
`,
			wantErr: `Posture "posture:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "via-must-be-tag-grant",
			input: `
{
  "grants": [
    {
      "src": [
        "*"
      ],
      "dst": [
        "*"
      ],
	  "ip": ["*"],
	  "via": ["autogroup:internet"]
    }
  ]
}
`,
			wantErr: `tag has to start with "tag:", got: "autogroup:internet"`,
		},
		{
			name: "grant-ip-port-zero-is-err",
			input: `
			{
  "grants": [
    {
      "src": [
        "*"
      ],
      "dst": [
        "100.64.0.1"
      ],
	  "ip": ["tcp:0"]
    }
  ]
}
`,
			wantErr: `first port must be >0, or use '*' for wildcard`,
		},

		{
			name: "disallow-unsupported-fields-grants-level",
			input: `
{
  "grants": [
    {
      "invalid_action": "accept",
      "src": ["*"],
      "dst": ["*"]
    }
  ]
}
`,
			wantErr: `unknown field "invalid_action"`,
		},
	}

	cmps := append(util.Comparers,
		cmp.Comparer(func(x, y Prefix) bool {
			return x == y
		}),
		cmp.Comparer(func(x, y tailcfg.RawMessage) bool {
			// Compare RawMessages by unmarshalling them to interface{}
			var xi, yi interface{}
			if err := oldJson.Unmarshal([]byte(x), &xi); err != nil {
				return false
			}
			if err := oldJson.Unmarshal([]byte(y), &yi); err != nil {
				return false
			}
			return cmp.Equal(xi, yi, util.Comparers...)
		}),
		cmpopts.IgnoreUnexported(Policy{}),
	)

	// For round-trip testing, we'll normalize the policies before comparing

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshalling
			policy, err := unmarshalPolicy([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unmarshalling: got %v; want no error", err)
				}
			} else {
				if err == nil {
					t.Fatalf("unmarshalling: got nil; want error %q", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("unmarshalling: got err %v; want error %q", err, tt.wantErr)
				}

				return // Skip the rest of the test if we expected an error
			}

			if diff := cmp.Diff(tt.want, policy, cmps...); diff != "" {
				t.Fatalf("unexpected policy (-want +got):\n%s", diff)
			}

			// Test round-trip marshalling/unmarshalling
			if policy != nil {
				// Marshal the policy back to JSON
				marshalled, err := oldJson.MarshalIndent(policy, "", "  ")
				if err != nil {
					t.Fatalf("marshalling: %v", err)
				}

				// Unmarshal it again
				roundTripped, err := unmarshalPolicy(marshalled)
				if err != nil {
					t.Fatalf("round-trip unmarshalling: %v", err)
				}

				// Add EquateEmpty to handle nil vs empty maps/slices
				roundTripCmps := append(cmps,
					cmpopts.EquateEmpty(),
					cmpopts.IgnoreUnexported(Policy{}),
				)

				// Compare using the enhanced comparers for round-trip testing
				if diff := cmp.Diff(policy, roundTripped, roundTripCmps...); diff != "" {
					t.Fatalf("round trip policy (-original +roundtripped):\n%s", diff)
				}
			}
		})
	}
}

// When separate ACL rules exist (one with autogroup:self, one with tag:router),
// the autogroup:self rule should not prevent the tag:router rule from working.
// This ensures that autogroup:self doesn't interfere with other ACL rules.
func TestGrantsWithCaps(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "test-1", Email: "test-1@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "test-2", Email: "test-2@example.com"},
	}

	// test-1 has a regular device
	test1Node := &types.Node{
		ID:       1,
		Hostname: "test-1-device",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     users[0],
		UserID:   users[0].ID,
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// test-2 has a router device with tag:node-router
	test2RouterNode := &types.Node{
		ID:         2,
		Hostname:   "test-2-router",
		IPv4:       ap("100.64.0.2"),
		IPv6:       ap("fd7a:115c:a1e0::2"),
		User:       users[1],
		UserID:     users[1].ID,
		ForcedTags: []string{"tag:node-router"},
		Hostinfo:   &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{test1Node, test2RouterNode}

	// This matches the exact policy from issue #2838:
	// - First rule: autogroup:member -> autogroup:self (allows users to see their own devices)
	// - Second rule: group:home -> tag:node-router (should allow group members to see router)
	policy := `{
		"groups": {
			"group:home": ["test-1@example.com", "test-2@example.com"]
		},
		"tagOwners": {
			"tag:node-router": ["group:home"]
		},
		"grants": [
			{
				"src": ["autogroup:member"],
				"dst": ["tag:node-router"],
				"app": {"tailscale.com/cap/test": []}
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// test-1 (in group:home) should see:
	// 1. Their own node (from autogroup:self rule)
	// 2. The router node (from group:home -> tag:node-router rule)
	test1Peers := peerMap[test1Node.ID]

	// Verify test-1 can see the router (group:home -> tag:node-router rule)
	require.True(t, slices.ContainsFunc(test1Peers, func(n types.NodeView) bool {
		return n.ID() == test2RouterNode.ID
	}), "test-1 should see test-2's router via group:home -> tag:node-router rule.")

	// Verify that test-1 has filter rules (including autogroup:self and tag:node-router access)
	rules, err := pm.FilterForNode(test2RouterNode.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules, "test-2 should see router's cap")
}
