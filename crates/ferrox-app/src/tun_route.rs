//! The `auto_route` switch: the default route the TUN device captures, the
//! prefixes the config names, and the prefixes it keeps off the tunnel, all
//! installed through the platform's routing table and removed when the inbound
//! stops.

use std::io;
use std::net::IpAddr;

use route_manager::{Route, RouteManager};

/// What one open device captures: the half-default of each family it carries,
/// the prefixes the config names, and the prefixes it must not capture.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    routes: Vec<(IpAddr, u8)>,
    keep: Vec<(IpAddr, u8)>,
}

impl Plan {
    /// Build the plan. A family is captured only when the device carries an
    /// address of it, so a v4-only tunnel does not blackhole v6. An excluded
    /// prefix keeps whatever route already carried it, pinned before the
    /// half-defaults land so longest-prefix still sends it where it went.
    pub(crate) fn new(v4: bool, v6: bool, routes: &[(IpAddr, u8)], keep: &[(IpAddr, u8)]) -> Self {
        let mut plan = Self {
            routes: Vec::new(),
            keep: keep.to_vec(),
        };
        let kept = |address: IpAddr, prefix: u8| {
            keep.iter().any(|(outer, outer_prefix)| {
                same_family(*outer, address) && covers(*outer, *outer_prefix, address, prefix)
            })
        };
        if v4 {
            for half in [
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)),
            ] {
                if !kept(half, 1) {
                    plan.routes.push((half, 1));
                }
            }
        }
        if v6 {
            for half in [
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                IpAddr::V6(std::net::Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            ] {
                if !kept(half, 1) {
                    plan.routes.push((half, 1));
                }
            }
        }
        for (address, prefix) in routes {
            if plan.routes.contains(&(*address, *prefix)) || kept(*address, *prefix) {
                continue;
            }
            plan.routes.push((*address, *prefix));
        }
        plan
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The prefixes the plan captures, in install order.
    pub(crate) fn routes(&self) -> &[(IpAddr, u8)] {
        &self.routes
    }

    /// The prefixes the plan leaves where they were.
    pub(crate) fn keep(&self) -> &[(IpAddr, u8)] {
        &self.keep
    }
}

/// The routes one device holds; dropping the guard puts the table back.
pub(crate) struct Guard {
    manager: RouteManager,
    added: Vec<Route>,
}

impl Guard {
    /// Pin every kept prefix where it already resolves, then capture the plan's
    /// prefixes on `interface`. A prefix whose current route cannot be found is
    /// named and left to the half-defaults, which is the same table the
    /// reference leaves it in.
    pub(crate) fn install(interface: &str, plan: &Plan) -> io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let mut added: Vec<Route> = Vec::with_capacity(plan.routes.len() + plan.keep.len());
        for (destination, prefix) in plan.keep() {
            match manager.find_route(destination) {
                Ok(Some(found)) => {
                    let mut pin = Route::new(*destination, *prefix);
                    if let Some(gateway) = found.gateway() {
                        pin = pin.with_gateway(gateway);
                    }
                    if let Some(name) = found.if_name() {
                        pin = pin.with_if_name(name.clone());
                    } else if let Some(index) = found.if_index() {
                        pin = pin.with_if_index(index);
                    }
                    if manager.add(&pin).is_ok() {
                        added.push(pin);
                    } else {
                        eprintln!(
                            "tun inbound: could not keep {destination}/{prefix} on its own route"
                        );
                    }
                }
                Ok(None) => eprintln!(
                    "tun inbound: no route carries {destination}/{prefix} yet; the tunnel may capture it"
                ),
                Err(error) => eprintln!(
                    "tun inbound: could not read the route for {destination}/{prefix}: {error}"
                ),
            }
        }
        for (destination, prefix) in plan.routes() {
            let route = Route::new(*destination, *prefix).with_if_name(interface.to_owned());
            match manager.add(&route) {
                Ok(()) => added.push(route),
                Err(error) => eprintln!(
                    "tun inbound: could not route {destination}/{prefix} into {interface}: {error}"
                ),
            }
        }
        Ok(Self { manager, added })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        for route in self.added.drain(..).rev() {
            let _ = self.manager.delete(&route);
        }
    }
}

fn same_family(outer: IpAddr, inner: IpAddr) -> bool {
    outer.is_ipv4() == inner.is_ipv4()
}

/// Whether `outer/prefix` contains `inner/inner_prefix`, by masked bits alone.
fn covers(outer: IpAddr, prefix: u8, inner: IpAddr, inner_prefix: u8) -> bool {
    if prefix > inner_prefix {
        return false;
    }
    match (outer, inner) {
        (IpAddr::V4(outer), IpAddr::V4(inner)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(outer) & mask == u32::from(inner) & mask
        }
        (IpAddr::V6(outer), IpAddr::V6(inner)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix.min(128)))
                .unwrap_or(0);
            u128::from(outer) & mask == u128::from(inner) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_v4_device_captures_only_the_v4_halves() {
        let plan = Plan::new(true, false, &[], &[]);
        assert_eq!(
            plan.routes(),
            &[
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
                (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
            ]
        );
    }

    #[test]
    fn a_dual_device_captures_both_halves() {
        let plan = Plan::new(true, true, &[], &[]);
        assert_eq!(plan.routes().len(), 4);
        assert_eq!(plan.routes()[2], (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1));
    }

    #[test]
    fn a_named_route_inside_a_kept_prefix_is_dropped() {
        let keep = [(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)];
        let plan = Plan::new(
            true,
            false,
            &[
                (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
                (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
            ],
            &keep,
        );
        assert!(plan
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16)));
        assert!(!plan
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16)));
    }

    #[test]
    fn a_kept_default_route_skips_the_family_halves() {
        let keep = [
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ];
        let plan = Plan::new(true, true, &[], &keep);
        assert!(plan.routes().is_empty(), "{:?}", plan.routes());
    }

    #[test]
    fn an_equal_prefix_is_contained() {
        let route = (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16);
        let plan = Plan::new(true, false, &[route], &[route]);
        assert!(!plan.routes().contains(&route));
        let host = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32);
        let plan = Plan::new(true, false, &[host], &[host]);
        assert!(!plan.routes().contains(&host));
        let v6 = (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            128,
        );
        let plan = Plan::new(false, true, &[v6], &[v6]);
        assert!(!plan.routes().contains(&v6));
    }

    #[test]
    fn a_duplicate_route_is_installed_once() {
        let route = (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15);
        let plan = Plan::new(true, false, &[route, route], &[]);
        assert_eq!(
            plan.routes()
                .iter()
                .filter(|named| **named == route)
                .count(),
            1
        );
    }

    #[test]
    fn containment_is_masked_bits_not_bytes() {
        let outer = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0));
        let inner = IpAddr::V4(Ipv4Addr::new(172, 31, 255, 1));
        assert!(covers(outer, 12, inner, 32));
        assert!(!covers(outer, 16, inner, 32));
        assert!(!covers(inner, 32, outer, 12));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let v6_inner = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0));
        assert!(covers(v6, 32, v6_inner, 64));
        assert!(covers(v6, 48, v6_inner, 64));
        let v6_out = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0));
        assert!(!covers(v6, 48, v6_out, 64));
    }
}
