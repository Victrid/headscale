package v2

import (
	"fmt"
	"strings"

	"github.com/go-json-experiment/json"
	"tailscale.com/tailcfg"
)

// This file implements the Grant-related types which is intended to replace ACL.
// Ref:
// https://tailscale.com/kb/1538/grants-syntax
// https://tailscale.com/kb/1324/grants

// NetCap implements https://tailscale.com/kb/1324/grants#network-capabilities
type NetCap struct {
	Protocol Protocol
	Port     []tailcfg.PortRange
}

func (ip *NetCap) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch vs := v.(type) {
	case string:
		if strings.Contains(vs, ":") {
			//<proto>:* or <proto>:<port>
			protos, ports, err := splitDestinationAndPort(vs)
			if err != nil {
				return err
			}
			// Use the json unmarshaller to parse the protocol string
			err = ip.Protocol.UnmarshalJSON([]byte(protos))
			if err != nil {
				return err
			}

			ip.Port, err = parsePortRange(ports)
			if err != nil {
				return err
			}
		} else {
			// <port>
			ip.Protocol = ""
			portRange, err := parsePortRange(vs)
			if err != nil {
				return err
			}
			ip.Port = portRange
		}

	default:
		return fmt.Errorf("type %T not supported", vs)
	}

	return nil
}

func (ip *NetCap) MarshalJSON() ([]byte, error) {
	var protoStr string
	if ip.Protocol != "" {
		protoBytes, err := ip.Protocol.MarshalJSON()
		if err != nil {
			return nil, err
		}
		protoStr = string(protoBytes)
	}

	var portStrs []string
	for _, pr := range ip.Port {
		if pr == tailcfg.PortRangeAny {
			portStrs = append(portStrs, "*")
		} else if pr.First == pr.Last {
			portStrs = append(portStrs, fmt.Sprintf("%d", pr.First))
		} else {
			portStrs = append(portStrs, fmt.Sprintf("%d-%d", pr.First, pr.Last))
		}
	}
	portStr := strings.Join(portStrs, ",")

	if protoStr != "" {
		return json.Marshal(fmt.Sprintf("%s:%s", protoStr, portStr))
	}
	return json.Marshal(portStr)
}

type AppCap map[string][]tailcfg.RawMessage

func (app *AppCap) ToPeerCapMap() tailcfg.PeerCapMap {
	CapMap := make(tailcfg.PeerCapMap)
	for name, appDefs := range *app {
		peerCap := tailcfg.PeerCapability(name)
		CapMap[peerCap] = appDefs
	}
	return CapMap
}

func (app *AppCap) validate() error {
	if app == nil {
		return fmt.Errorf("AppCap is nil")
	}
	// Name should be domain / app format
	for name, _ := range *app {
		if !strings.Contains(name, "/") {
			return fmt.Errorf("invalid app capability name: %s", name)
		}
		// Split and validate domain and app name
		parts := strings.SplitN(name, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid app capability name: %s", name)
		}
		// Parts[0] should be a valid domain (basic check)
		if strings.ContainsAny(parts[0], " !@#$%^&*()+=[]{}|\\;:'\",<>/?") {
			return fmt.Errorf("invalid domain in app capability name: %s", name)
		}
	}
	return nil
}

func (app *AppCap) UnmarshalJSON(b []byte) error {
	type appCapAlias AppCap
	var temp appCapAlias

	if err := json.Unmarshal(b, &temp); err != nil {
		return err
	}

	*app = AppCap(temp)

	if err := app.validate(); err != nil {
		return err
	}

	return nil
}

// SrcPosture are string prefixed with "posture:" representing postures.
type SrcPosture string

func isSrcPosture(str string) bool {
	return strings.HasPrefix(str, "posture:")
}

func (t SrcPosture) Validate() error {
	if isSrcPosture(string(t)) {
		return nil
	}
	return fmt.Errorf(`posture has to start with "posture:", got: %q`, t)
}

func (t *SrcPosture) UnmarshalJSON(b []byte) error {
	*t = SrcPosture(strings.Trim(string(b), `"`))
	if err := t.Validate(); err != nil {
		return err
	}

	return nil
}

// Postures is the mapping of posture names to list of check strings.
// https://tailscale.com/kb/1288/device-posture
type Postures map[SrcPosture][]string

func (p *Postures) UnmarshalJSON(b []byte) error {
	type posturesAlias Postures
	var temp posturesAlias

	if err := json.Unmarshal(b, &temp); err != nil {
		return err
	}

	*p = Postures(temp)

	// Validate each posture
	for posture, _ := range *p {
		if err := posture.Validate(); err != nil {
			return err
		}

		// TODO: actual posture checking strings are not validated
	}

	return nil
}

// Grant represents the grants structure in a policy.
type Grant struct {
	Sources      Aliases      `json:"src"`
	Destinations Aliases      `json:"dst"`
	IPs          []NetCap     `json:"ip,omitempty"`
	App          AppCap       `json:"app,omitempty"`
	SrcPostures  []SrcPosture `json:"srcPosture,omitempty"`
	// Via must be tags
	Via []Tag `json:"via,omitempty"`
}

func (g *Grant) Validate() error {
	// IPs and App are mutually exclusive
	if len(g.IPs) > 0 && len(g.App) > 0 {
		return fmt.Errorf("IPs and App capabilities are mutually exclusive in a grant")
	}
	return nil
}

func (g *Grant) UnmarshalJSON(b []byte) error {
	// First unmarshal into a map to filter out comment fields
	var raw map[string]any
	if err := json.Unmarshal(b, &raw, policyJSONOpts...); err != nil {
		return err
	}

	// Remove any fields that start with '#'
	filtered := make(map[string]any)
	for key, value := range raw {
		if !strings.HasPrefix(key, "#") {
			filtered[key] = value
		}
	}

	// Marshal the filtered map back to JSON
	filteredBytes, err := json.Marshal(filtered)
	if err != nil {
		return err
	}

	// Create a type alias to avoid infinite recursion
	type grantAlias Grant
	var temp grantAlias

	// Unmarshal into the temporary struct using the v2 JSON options
	if err := json.Unmarshal(filteredBytes, &temp, policyJSONOpts...); err != nil {
		return err
	}

	// Copy the result back to the original struct
	*g = Grant(temp)

	if err := g.Validate(); err != nil {
		return err
	}

	return nil
}
