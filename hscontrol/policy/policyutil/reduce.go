package policyutil

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

// ReduceFilterRules takes a node and a set of global filter rules and removes all rules
// and destinations that are not relevant to that particular node.
//
// IMPORTANT: This function is designed for global filters only. Per-node filters
// (from autogroup:self policies) are already node-specific and should not be passed
// to this function. Use PolicyManager.FilterForNode() instead, which handles both cases.
func ReduceFilterRules(node types.NodeView, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}

	for _, rule := range rules {
		// record if the rule is actually relevant for the given node.
		var dests []tailcfg.NetPortRange
	DEST_LOOP:
		for _, dest := range rule.DstPorts {
			expanded, err := util.ParseIPSet(dest.IP, nil)
			// Fail closed, if we can't parse it, then we should not allow
			// access.
			if err != nil {
				continue DEST_LOOP
			}

			if node.InIPSet(expanded) {
				dests = append(dests, dest)
				continue DEST_LOOP
			}

			// If the node exposes routes, ensure they are note removed
			// when the filters are reduced.
			if node.Hostinfo().Valid() {
				routableIPs := node.Hostinfo().RoutableIPs()
				if routableIPs.Len() > 0 {
					for _, routableIP := range routableIPs.All() {
						if expanded.OverlapsPrefix(routableIP) {
							dests = append(dests, dest)
							continue DEST_LOOP
						}
					}
				}
			}

			// Also check approved subnet routes - nodes should have access
			// to subnets they're approved to route traffic for.
			subnetRoutes := node.SubnetRoutes()

			for _, subnetRoute := range subnetRoutes {
				if expanded.OverlapsPrefix(subnetRoute) {
					dests = append(dests, dest)
					continue DEST_LOOP
				}
			}
		}

		if len(dests) > 0 {
			ret = append(ret, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: dests,
				IPProto:  rule.IPProto,
			})
		}

		var capGrants []tailcfg.CapGrant

		for _, capGrant := range rule.CapGrant {
			var destPref []netip.Prefix
		GRANT_LOOP:
			for _, dest := range capGrant.Dsts {
				expanded, err := util.ParseIPSet(dest.String(), nil)
				// Fail closed, if we can't parse it, then we should not allow
				// access.
				if err != nil {
					continue GRANT_LOOP
				}

				if node.InIPSet(expanded) {
					destPref = append(destPref, dest)
					continue GRANT_LOOP
				}

				// If the node exposes routes, ensure they are note removed
				// when the filters are reduced.
				if node.Hostinfo().Valid() {
					routableIPs := node.Hostinfo().RoutableIPs()
					if routableIPs.Len() > 0 {
						for _, routableIP := range routableIPs.All() {
							if expanded.OverlapsPrefix(routableIP) {
								destPref = append(destPref, dest)
								continue GRANT_LOOP
							}
						}
					}
				}

				// Also check approved subnet routes - nodes should have access
				// to subnets they're approved to route traffic for.
				subnetRoutes := node.SubnetRoutes()

				for _, subnetRoute := range subnetRoutes {
					if expanded.OverlapsPrefix(subnetRoute) {
						destPref = append(destPref, dest)
						continue GRANT_LOOP
					}
				}
			}

			if len(destPref) > 0 {
				capGrants = append(capGrants, tailcfg.CapGrant{
					Dsts:   destPref,
					Caps:   capGrant.Caps,
					CapMap: capGrant.CapMap,
				})
			}
		}

		if len(capGrants) > 0 {
			ret = append(ret, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				CapGrant: capGrants,
			})
		}
	}

	return ret
}
