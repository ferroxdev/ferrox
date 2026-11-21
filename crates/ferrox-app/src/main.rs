// The census is a test-shape instrument: here its call expands to nothing, so no shipped relay carries a map, a lock or a name.
#[cfg(not(test))]
macro_rules! census {
    ($name:literal, $fd:expr, $armed:expr) => {};
}

// The counting allocator is core's and the window is one thread's: installed only for the test binary, so a shipped flow keeps the system allocator.
#[cfg(test)]
#[global_allocator]
static ALLOC_COUNT: ferrox_core::alloc_count::Counting = ferrox_core::alloc_count::Counting;

mod accesslog;
mod address_port;
mod anytls;
mod budgets;
#[cfg(test)]
#[macro_use]
mod census;
mod blackhole;
mod browser_dialer;
mod commander;
mod config;
mod conn;
mod dnsapp;
mod dnsnet;
mod ech_dns;
mod fastopen;
mod foxy;
mod foxy_account;
mod foxy_browser;
mod foxy_catalog;
mod foxy_challenge;
mod foxy_latency;
#[cfg(test)]
mod foxy_live;
mod geodata;
mod grpc;
mod h2;
mod headers;
mod httpheader;
mod httpupgrade;
mod hysteria;
mod hysteria_realm;
mod hysteria_v1;
mod json;
mod limit;
mod masque;
mod masque_h1;
mod masque_h2;
mod metrics;
mod muxpool;
mod noize;
mod observatory;
mod policy;
mod process;
mod proxy;
mod psiphon;
mod psiphon_broker;
mod psiphon_burst;
mod psiphon_cdn;
mod psiphon_dns;
mod psiphon_fragment;
mod psiphon_geoip;
mod psiphon_h3;
mod psiphon_light;
mod psiphon_meek;
mod psiphon_osl;
mod psiphon_packet_tunnel;
mod psiphon_quic;
mod psiphon_rate;
mod psiphon_replay;
mod psiphon_shadowsocks;
mod psiphon_ssh;
mod psiphon_tactics;
mod psiphon_user_agent;
mod psiphon_webrtc;
mod quic;
mod reverse;
mod router;
mod router_script;
mod shadowsocks;
mod shadowsocks2022;
mod singmux;
mod sniff;
mod sockopt;
mod socks;
mod stats;
mod transparent;
mod tuic;
mod tun;
mod tun_stack;
#[cfg(unix)]
mod tun_system;
mod veepn;
mod vision;
mod vmess;
mod warp;
mod warp_scan;
mod webhook;
mod wg;
#[cfg(target_os = "linux")]
mod wg_kernel;
mod wg_stack;
mod wireguard;
mod ws;
mod xdrive;
mod xhttp;
mod xhttp_h2;
mod xhttp_h3;
mod xmux;
mod xray_pb;

use ferrox_core::policy::UnsafeOptIn;
use ferrox_core::transport::Support;
use std::io::Read as _;
use std::io::Write as _;
use std::time::Duration;

/// Set by `-test`, so the startup exits answer xray's way: `Failed to start:` and status 23.
static TEST_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn test_only() -> bool {
    TEST_ONLY.load(std::sync::atomic::Ordering::Relaxed)
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  ferrox-app check <vless://...|trojan://...> [--allow-unsafe-fp] [--allow-plaintext-public]");
    eprintln!("                                parse + support + header len (no network)");
    eprintln!("  ferrox-app run <vless://...|trojan://...> [same flags]   check + TCP reachability (sends nothing)");
    eprintln!("  ferrox-app version                print the serving binary's version");
    eprintln!("  ferrox-app x25519                 print a fresh X25519 keypair");
    eprintln!("  ferrox-app run -c <config.json>   serve inbounds until killed");
    eprintln!("  ferrox-app -config=<file|stdin:> [-format=json|pb]   same, xray's own invocation");
    eprintln!(
        "  ferrox-app -confdir <dir>        merge every config file in the directory, as xray does"
    );
    eprintln!("  ferrox-app -dump                 print the merged config and exit");
    eprintln!(
        "  ferrox-app -test -c <config.json>  build every handler and exit, as xray's -test does"
    );
    eprintln!(
        "  ferrox-app [no arguments]         serve a discovered config.json, or stdin, as xray does"
    );
    eprintln!("  ferrox-app mint-foxy-pass -c <config.json> -o <pass.json>");
    eprintln!("                                sign in once, store the proxy pass (0600)");
    eprintln!("  ferrox-app warp-register [--register masque|wg|gool|gool-classic|mim|all]");
    eprintln!(
        "        [-o|--config FILE] [--wg-config FILE] [--masque-config FILE] [--api URL] [--api-address ADDR]"
    );
    eprintln!("        [--mode auto|wireguard|masque|gool|gool-classic|mim] [--gool-classic] [--wiw-outer ADDR] [--wiw-inner ADDR] [--mim-outer ADDR] [--mim-inner ADDR] [--noize off|light|firewall|balanced|gfw|aggressive] [--no-profile-retry] [--no-quic-v2]");
    eprintln!(
        "                                with --register, make the kind's identities and print them; without it, register one device, save the identity (0600 on Unix), print the outbound"
    );
    eprintln!(
        "  ferrox-app browser-login --email ADDR --token-file PATH [--code CODE] [--no-open]"
    );
    eprintln!("                                finish the Firefox sign-in in a real browser");
    eprintln!(
        "  ferrox-app edges [--ping]         list the catalogue's edges as JSON rows; --ping adds a handshake ms (null when silent)"
    );
    eprintln!(
        "  ferrox-app psiphon-regions -c <config.json>   list the signed server list's region codes"
    );
    eprintln!(
        "  ferrox-app psiphon-tactics -c <config.json>   fetch tactics and print broker specs"
    );
    eprintln!(
        "  ferrox-app psiphon-broker -c <config.json> [--sdp <file>]  send a client offer to the first broker"
    );
    eprintln!(
        "  ferrox-app psiphon-feedback -c <config.json> --diagnostics <file> [--upload-path <path>]"
    );
    eprintln!("  ferrox-app psiphon-exchange export -c <config.json>   print an exchange payload");
    eprintln!("  ferrox-app psiphon-exchange import -c <config.json> <payload>   import one");
    std::process::exit(2);
}

/// One share link plus any out-of-band consent flags, in either order.
fn link_and_opt_in<I: Iterator<Item = String>>(args: &mut I) -> (String, UnsafeOptIn) {
    let mut link: Option<String> = None;
    let mut opt = UnsafeOptIn::none();
    for arg in args {
        match arg.as_str() {
            "--allow-unsafe-fp" => opt = opt.allow_unsafe_fingerprint(),
            "--allow-plaintext-public" => opt = opt.allow_plaintext_to_public(),
            _ if link.is_none() => link = Some(arg),
            _ => usage(),
        }
    }
    match link {
        Some(link) => (link, opt),
        None => usage(),
    }
}

enum Link {
    Vless(ferrox_core::vless::VlessLink),
    Trojan(ferrox_core::trojan::TrojanLink),
}

impl Link {
    fn parse(text: &str) -> Self {
        if text.starts_with(ferrox_core::trojan::SCHEME) {
            return ferrox_core::trojan::TrojanLink::parse(text).map_or_else(
                |e| {
                    eprintln!("bad link: {e}");
                    std::process::exit(1);
                },
                Self::Trojan,
            );
        }
        ferrox_core::vless::VlessLink::parse(text).map_or_else(
            |e| {
                eprintln!("bad link: {e}");
                std::process::exit(1);
            },
            Self::Vless,
        )
    }

    fn describe(&self, opt_in: UnsafeOptIn) -> String {
        match self {
            Self::Vless(link) => format!(
                "host={} port={} type={} security={} flow={} support=[{}]",
                link.host,
                link.port,
                link.param("type"),
                link.param("security"),
                link.flow(),
                link.support_opted(opt_in),
            ),
            Self::Trojan(link) => format!(
                "host={} port={} type={} security={} header={} support=[{}]",
                link.host,
                link.port,
                link.param("type"),
                link.param("security"),
                match link.header_type() {
                    "" => "none",
                    header => header,
                },
                link.support_opted(opt_in),
            ),
        }
    }

    fn support_opted(&self, opt_in: UnsafeOptIn) -> Support {
        match self {
            Self::Vless(link) => link.support_opted(opt_in),
            Self::Trojan(link) => link.support_opted(opt_in),
        }
    }

    fn authority(&self) -> (&str, u16) {
        match self {
            Self::Vless(link) => (&link.host, link.port),
            Self::Trojan(link) => (&link.host, link.port),
        }
    }

    /// A header for the same probe destination either way, so `check` prints one number for both schemes.
    fn header(&self) -> Vec<u8> {
        match self {
            Self::Vless(link) => link.encode_request_header("example.com", 443),
            Self::Trojan(link) => {
                link.encode_header(ferrox_core::trojan::Command::Connect, "example.com", 443)
            }
        }
    }
}

fn cmd_check(link_str: &str, opt_in: UnsafeOptIn) {
    let link = Link::parse(link_str);
    println!("{}", link.describe(opt_in));
    let hdr = link.header();
    println!(
        "header_len={} header_prefix={:02x?}",
        hdr.len(),
        &hdr[..8.min(hdr.len())]
    );
    match link.support_opted(opt_in) {
        Support::Implemented { method } => {
            println!("diallable: {method} (run checks tcp reachability; sends nothing)");
        }
        Support::Planned { reason } => println!("not yet diallable: {reason}"),
        Support::UnsafeRequiresOptIn { reason } => {
            println!("needs explicit opt-in (policy::UnsafeOptIn, or --allow-unsafe-fp / --allow-plaintext-public): {reason}");
        }
    }
}

fn cmd_run(link_str: &str, opt_in: UnsafeOptIn) {
    let link = Link::parse(link_str);
    println!("{}", link.describe(opt_in));
    match link.support_opted(opt_in) {
        Support::Implemented { .. } => {}
        other => {
            eprintln!("refusing to dial: {other}");
            eprintln!("(parse succeeded; the transport rung is not implemented yet)");
            std::process::exit(3);
        }
    }
    let (host, port) = link.authority();
    let addr = format!("{host}:{port}");
    let sock: std::net::SocketAddr = if let Ok(sock) = addr.parse() {
        sock
    } else {
        use std::net::ToSocketAddrs as _;
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| {
                eprintln!("cannot resolve {addr}");
                std::process::exit(1);
            })
    };
    let t0 = std::time::Instant::now();
    match std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(8)) {
        Ok(stream) => {
            let dt = t0.elapsed();
            println!("tcp reachable in {dt:?} (no bytes sent; session handshake is the next rung)");
            drop(stream);
        }
        Err(e) => {
            eprintln!("tcp unreachable: {e}");
            std::process::exit(4);
        }
    }
    let hdr = link.header();
    println!("header_len={} (encoded locally, not sent)", hdr.len());
    let _ = std::io::stdout().flush();
}

fn cmd_psiphon_regions<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let text = if path == "-" || path == "stdin:" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .unwrap_or_else(|error| {
                eprintln!("psiphon-regions: stdin: {error}");
                std::process::exit(1);
            });
        text
    } else {
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            eprintln!("psiphon-regions: {path}: {error}");
            std::process::exit(1);
        })
    };
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("psiphon-regions: {error}");
        std::process::exit(1);
    });
    let settings = root
        .get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"));
    match psiphon::regions(settings) {
        Ok(rows) => {
            for (region, count) in rows {
                println!("{region}\t{count}");
            }
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn cmd_psiphon_tactics<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let text = if path == "-" || path == "stdin:" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .unwrap_or_else(|error| {
                eprintln!("psiphon-tactics: stdin: {error}");
                std::process::exit(1);
            });
        text
    } else {
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            eprintln!("psiphon-tactics: {path}: {error}");
            std::process::exit(1);
        })
    };
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("psiphon-tactics: {error}");
        std::process::exit(1);
    });
    let settings = root
        .get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"));
    match psiphon::tactics(settings) {
        Ok(tactics) => {
            println!("tag\t{}", tactics.tag);
            println!("ttl\t{}", tactics.ttl);
            for broker in tactics.brokers {
                println!(
                    "broker\t{}\t{}\t{}",
                    broker.public_key,
                    broker.root_secret,
                    broker
                        .fronts
                        .iter()
                        .map(|front| front.host.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            for compartment in tactics.compartments {
                println!("compartment\t{compartment}");
            }
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn read_psiphon_settings(path: &str, label: &str) -> Option<json::Json> {
    let text = if path == "-" || path == "stdin:" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .unwrap_or_else(|error| {
                eprintln!("{label}: stdin: {error}");
                std::process::exit(1);
            });
        text
    } else {
        std::fs::read_to_string(path).unwrap_or_else(|error| {
            eprintln!("{label}: {path}: {error}");
            std::process::exit(1);
        })
    };
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("{label}: {error}");
        std::process::exit(1);
    });
    root.get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"))
        .cloned()
}

fn cmd_psiphon_feedback<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    let mut diagnostics_path = String::new();
    let mut upload_path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            "--diagnostics" => {
                diagnostics_path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--diagnostics=") => {
                diagnostics_path.clear();
                diagnostics_path.push_str(&other["--diagnostics=".len()..]);
            }
            "--upload-path" => {
                upload_path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--upload-path=") => {
                upload_path.clear();
                upload_path.push_str(&other["--upload-path=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() || diagnostics_path.is_empty() {
        usage();
    }
    let diagnostics = std::fs::read(&diagnostics_path).unwrap_or_else(|error| {
        eprintln!("psiphon-feedback: {diagnostics_path}: {error}");
        std::process::exit(1);
    });
    let settings = read_psiphon_settings(&path, "psiphon-feedback");
    match psiphon::feedback(settings.as_ref(), &diagnostics, &upload_path) {
        Ok(()) => println!("uploaded"),
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn cmd_psiphon_exchange<I: Iterator<Item = String>>(args: &mut I) {
    let action = args.next().unwrap_or_else(|| usage());
    let mut path = String::new();
    let mut payload = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            other if payload.is_empty() => payload.push_str(other),
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let settings = read_psiphon_settings(&path, "psiphon-exchange");
    match action.as_str() {
        "export" => match psiphon::exchange_export(settings.as_ref()) {
            Ok(payload) => println!("{payload}"),
            Err(why) => {
                eprintln!("{why}");
                std::process::exit(1);
            }
        },
        "import" => {
            if payload.is_empty() || payload == "-" {
                let mut text = String::new();
                std::io::stdin()
                    .read_to_string(&mut text)
                    .unwrap_or_else(|error| {
                        eprintln!("psiphon-exchange: stdin: {error}");
                        std::process::exit(1);
                    });
                payload = text;
            }
            match psiphon::exchange_import(settings.as_ref(), &payload) {
                Ok(host) => println!("{host}"),
                Err(why) => {
                    eprintln!("{why}");
                    std::process::exit(1);
                }
            }
        }
        _ => usage(),
    }
}

fn cmd_psiphon_broker<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    let mut sdp_path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            "--sdp" => {
                sdp_path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--sdp=") => {
                sdp_path.clear();
                sdp_path.push_str(&other["--sdp=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        eprintln!("psiphon-broker: {path}: {error}");
        std::process::exit(1);
    });
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("psiphon-broker: {error}");
        std::process::exit(1);
    });
    let settings = root
        .get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"));
    let sdp = if sdp_path.is_empty() {
        None
    } else {
        Some(std::fs::read_to_string(&sdp_path).unwrap_or_else(|error| {
            eprintln!("psiphon-broker: {sdp_path}: {error}");
            std::process::exit(1);
        }))
    };
    match psiphon::broker_offer(settings, sdp.as_deref()) {
        Ok(offer) => {
            println!("limited\t{}", offer.limited);
            println!("no_match\t{}", offer.no_match);
            println!("must_upgrade\t{}", offer.must_upgrade);
            println!("connection_id_len\t{}", offer.connection_id.len());
            println!("protocol_version\t{}", offer.protocol_version);
            println!("answer_sdp\t{}", offer.answer_sdp);
            println!(
                "relay_packet_to_server\t{}",
                offer.relay_packet_to_server.len()
            );
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let _ = browser_dialer::active();
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        serve_from_flags(&[]);
    };
    match cmd.as_str() {
        "check" => {
            let (link, opt_in) = link_and_opt_in(&mut args);
            cmd_check(&link, opt_in);
        }
        "run" => {
            let rest: Vec<String> = args.collect();
            if rest.is_empty() || rest.first().is_some_and(|arg| is_serve_flag(arg)) {
                serve_from_flags(&rest);
            }
            let mut iter = rest.into_iter();
            let (link, opt_in) = link_and_opt_in(&mut iter);
            cmd_run(&link, opt_in);
        }
        "version" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_version();
        }
        "mint-foxy-pass" => {
            let next = args.next().unwrap_or_else(|| usage());
            if next != "-c" && next != "-config" {
                usage();
            }
            let config = args.next().unwrap_or_else(|| usage());
            let flag = args.next().unwrap_or_else(|| usage());
            if flag != "-o" {
                usage();
            }
            let out = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            proxy::mint_foxy_pass(&config, &out);
        }
        "browser-login" => {
            let mut email = String::new();
            let mut token_file = String::new();
            let mut code = String::new();
            let mut no_open = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--email" | "-e" => email = args.next().unwrap_or_else(|| usage()),
                    "--token-file" | "-t" => {
                        token_file = args.next().unwrap_or_else(|| usage());
                    }
                    "--code" => code = args.next().unwrap_or_else(|| usage()),
                    "--no-open" => no_open = true,
                    _ => usage(),
                }
            }
            if email.is_empty() || token_file.is_empty() {
                usage();
            }
            foxy_browser::login(
                &email,
                &token_file,
                (!code.is_empty()).then_some(code.as_str()),
                no_open,
            );
        }
        "warp-register" => warp::register_command(&mut args, usage),
        "edges" => {
            let mut ping = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--ping" => ping = true,
                    // A config is accepted and ignored for the spelling the docs already carry: the catalogue needs no lane.
                    "-c" | "-config" => {
                        args.next().unwrap_or_else(|| usage());
                    }
                    _ => usage(),
                }
            }
            proxy::print_foxy_edges(ping);
        }
        "psiphon-regions" => cmd_psiphon_regions(&mut args),
        "psiphon-tactics" => cmd_psiphon_tactics(&mut args),
        "psiphon-broker" => cmd_psiphon_broker(&mut args),
        "psiphon-feedback" => cmd_psiphon_feedback(&mut args),
        "psiphon-exchange" => cmd_psiphon_exchange(&mut args),
        "x25519" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_x25519();
        }
        _ if is_serve_flag(&cmd) => {
            let rest: Vec<String> = std::iter::once(cmd).chain(args).collect();
            serve_from_flags(&rest);
        }
        _ => usage(),
    }
}

/// A flag xray itself takes for a config; `run <link> --allow-unsafe-fp` is link mode.
fn is_serve_flag(arg: &str) -> bool {
    matches!(
        arg.split('=').next().unwrap_or(arg),
        "-c" | "-config" | "-confdir" | "-format" | "-test" | "-dump"
    )
}

/// xray's own invocation (`-config=stdin: -format=pb`) and the `run -c <file>` spelling this tree
/// shipped first; several files, a config dir or several `-c` files, merge before they serve.
fn serve_from_flags(args: &[String]) -> ! {
    let mut configs: Vec<String> = Vec::new();
    let mut confdir: Option<String> = None;
    let mut format: Option<String> = None;
    let mut dump = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        match flag {
            "-c" | "-config" | "-format" | "-confdir" => {
                let value = if let Some(value) = inline {
                    value
                } else {
                    i += 1;
                    args.get(i).cloned().unwrap_or_else(|| usage())
                };
                match flag {
                    "-format" => format = Some(value),
                    "-confdir" => confdir = Some(value),
                    _ => configs.push(value),
                }
            }
            "-test" => TEST_ONLY.store(true, std::sync::atomic::Ordering::Relaxed),
            "-dump" => dump = true,
            _ => usage(),
        }
        i += 1;
    }
    if let Some(dir) = confdir.as_deref() {
        read_conf_dir(dir, format.as_deref(), &mut configs);
    } else if let Some(dir) = conf_dir_env() {
        read_conf_dir(&dir, format.as_deref(), &mut configs);
    }
    if dump {
        dump_config(&configs, format.as_deref());
    }
    if configs.len() > 1 {
        serve_files(&configs, format.as_deref());
    }
    let source = configs.pop().unwrap_or_else(discover_config);
    let format = source_format(format.as_deref(), &source);
    let bytes = read_source(&source)
        .unwrap_or_else(|error| proxy::exit(&format!("cannot read {source}: {error}")));
    serve_source(&source, &bytes, format)
}

/// xray's `readConfDir`: every file the `-format` regex names, in `os.ReadDir`'s sorted order,
/// appended after the files `-c` named. A path that is not a directory is not an error there.
fn read_conf_dir(dir: &str, format: Option<&str>, out: &mut Vec<String>) {
    if !std::path::Path::new(dir).is_dir() {
        return;
    }
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| proxy::exit(&format!("cannot read {dir}: {error}")));
    let suffixes: &[&str] = match format.map(str::to_ascii_lowercase).as_deref() {
        Some("jsonc") => &["jsonc"],
        Some("toml") => &["toml"],
        Some("yaml" | "yml") => &["yaml", "yml"],
        _ => &["json", "jsonc", "toml", "yaml", "yml"],
    };
    let mut names: Vec<std::path::PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| {
                    suffixes
                        .iter()
                        .any(|suffix| extension.eq_ignore_ascii_case(suffix))
                })
        })
        .collect();
    names.sort();
    out.extend(
        names
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned()),
    );
}

/// `xray.location.confdir`, read only when `-confdir` named no directory.
fn conf_dir_env() -> Option<String> {
    std::env::var_os("xray.location.confdir")
        .or_else(|| std::env::var_os("XRAY_LOCATION_CONFDIR"))
        .map(|dir| dir.to_string_lossy().into_owned())
        .filter(|dir| std::path::Path::new(dir).is_dir())
}

/// xray's `MergeConfig`: every file decoded, then each later config overrides the one before by
/// its own `Override` rule. Protobuf is one file or none, as the reference's loader insists.
fn serve_files(files: &[String], format: Option<&str>) -> ! {
    let mut merged = crate::json::Json::Obj(Vec::new());
    for (at, file) in files.iter().enumerate() {
        let format = source_format(format, file);
        if matches!(format, SourceFormat::Protobuf) {
            proxy::exit("Only one protobuf config file is allowed");
        }
        let bytes = read_source(file)
            .unwrap_or_else(|error| proxy::exit(&format!("cannot read {file}: {error}")));
        let body = config_text(&bytes, format)
            .unwrap_or_else(|error| proxy::exit(&format!("bad config {file}: {error}")));
        let root = crate::json::parse(&body)
            .unwrap_or_else(|error| proxy::exit(&format!("bad config {file}: {error}")));
        if at == 0 {
            merged = root;
        } else {
            crate::json::merge(&mut merged, &root, file);
        }
    }
    let mut text = String::new();
    crate::json::write(&merged, &mut text);
    proxy::serve_json(&files.join(", "), &text, test_only());
}

/// xray's `-dump`: the merged config on stdout, without building or serving it. A file format the
/// reference has no decoder for is skipped, and a merge error is its status 23 with the reason on
/// stdout.
fn dump_config(configs: &[String], named: Option<&str>) -> ! {
    let files = if configs.is_empty() {
        vec![discover_config()]
    } else {
        configs.to_vec()
    };
    let mut merged = crate::json::Json::Obj(Vec::new());
    let mut first = true;
    for file in &files {
        let format = source_format(named, file);
        if matches!(format, SourceFormat::Protobuf) {
            continue;
        }
        let bytes = read_source(file)
            .unwrap_or_else(|error| dump_fail(&format!("cannot read {file}: {error}")));
        let body = config_text(&bytes, format)
            .unwrap_or_else(|error| dump_fail(&format!("bad config {file}: {error}")));
        let root = crate::json::parse(&body)
            .unwrap_or_else(|error| dump_fail(&format!("bad config {file}: {error}")));
        if first {
            merged = root;
            first = false;
        } else {
            crate::json::merge(&mut merged, &root, file);
        }
    }
    let mut text = String::new();
    crate::json::write(&merged, &mut text);
    println!("{text}");
    std::process::exit(0);
}

fn dump_fail(message: &str) -> ! {
    println!("{message}");
    std::process::exit(23);
}

#[derive(Clone, Copy)]
enum SourceFormat {
    Json,
    Jsonc,
    Yaml,
    Toml,
    Protobuf,
}

/// xray's search when no `-config` is given: a `config.*` in the working directory, then
/// `xray.location.config`'s `config.json` (the executable's directory when unset), then stdin.
fn discover_config() -> String {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(dir) = std::env::current_dir() {
        for name in [
            "config.json",
            "config.jsonc",
            "config.toml",
            "config.yaml",
            "config.yml",
        ] {
            candidates.push(dir.join(name));
        }
    }
    let installed = std::env::var_os("xray.location.config")
        .or_else(|| std::env::var_os("XRAY_LOCATION_CONFIG"))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        });
    candidates.extend(installed.map(|dir| dir.join("config.json")));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map_or_else(
            || "stdin:".to_owned(),
            |path| path.to_string_lossy().into_owned(),
        )
}

/// xray infers the format from the extension when `-format` is absent; a stream
/// has none, and JSON is this tree's own dialect.
fn source_format(named: Option<&str>, source: &str) -> SourceFormat {
    match named.map(str::to_ascii_lowercase).as_deref() {
        Some("pb" | "protobuf") => SourceFormat::Protobuf,
        Some("json") => SourceFormat::Json,
        Some("jsonc") => SourceFormat::Jsonc,
        Some("yaml" | "yml") => SourceFormat::Yaml,
        Some("toml") => SourceFormat::Toml,
        Some("auto") | None => {
            let extension = std::path::Path::new(source)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if extension.eq_ignore_ascii_case("pb") || extension.eq_ignore_ascii_case("protobuf") {
                SourceFormat::Protobuf
            } else if extension.eq_ignore_ascii_case("jsonc") {
                SourceFormat::Jsonc
            } else if extension.eq_ignore_ascii_case("yaml")
                || extension.eq_ignore_ascii_case("yml")
            {
                SourceFormat::Yaml
            } else if extension.eq_ignore_ascii_case("toml") {
                SourceFormat::Toml
            } else {
                SourceFormat::Json
            }
        }
        Some(other) => proxy::exit(&format!("unknown config format `{other}`")),
    }
}

/// A config source as xray reads it: a stream, an HTTP(S) URL, a socket endpoint, or a file.
fn read_source(source: &str) -> Result<Vec<u8>, String> {
    if source == "stdin" || source == "stdin:" {
        let mut bytes = Vec::new();
        return std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)
            .map(|_| bytes)
            .map_err(|error| error.to_string());
    }
    if let Some((url, socket)) = remote_source(source) {
        return fetch_http(&url, socket.as_deref(), 10);
    }
    if let Some((scheme, _)) = source.split_once("://") {
        return Err(format!(
            "unsupported config source `{source}`: scheme `{scheme}`"
        ));
    }
    std::fs::read(source).map_err(|error| error.to_string())
}

/// The forms `ConfigLoader` sends to `FetchHTTPContent`, plus its deprecated `http+unix://` spelling.
fn remote_source(source: &str) -> Option<(String, Option<String>)> {
    if let Some(raw) = source.strip_prefix("http+unix://") {
        let canonical = if let Some(at) = raw.find(".sock/") {
            format!("{}:{}", &raw[..at + 5], &raw[at + 5..])
        } else {
            raw.to_owned()
        };
        if canonical.starts_with('/') || canonical.starts_with('@') {
            return Some(split_http_unix_url(&canonical));
        }
        return Some((canonical, None));
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        return Some((source.to_owned(), None));
    }
    if let Some(raw) = source.strip_prefix("sock:") {
        if raw.starts_with('/') || raw.starts_with('@') {
            return Some(split_http_unix_url(raw));
        }
    }
    if source.starts_with('/') && (source.contains(":/") || is_unix_socket(source)) {
        return Some(split_http_unix_url(source));
    }
    if source.starts_with('@') {
        return Some(split_http_unix_url(source));
    }
    None
}

/// xray's `SplitHTTPUnixURL`: a socket path and an optional `:/path` HTTP target.
fn split_http_unix_url(raw: &str) -> (String, Option<String>) {
    if let Some(at) = raw.find(":/") {
        (
            format!("http://localhost{}", &raw[at + 1..]),
            Some(raw[..at].to_owned()),
        )
    } else {
        ("http://localhost/".to_owned(), Some(raw.to_owned()))
    }
}

#[cfg(unix)]
fn is_unix_socket(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
}

#[cfg(not(unix))]
fn is_unix_socket(_path: &str) -> bool {
    false
}

trait ReadWrite: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> ReadWrite for T {}

/// `FetchHTTPContent`: a 30-second request, redirects like `net/http`, status 200 only.
fn fetch_http(url: &str, socket: Option<&str>, redirects: usize) -> Result<Vec<u8>, String> {
    let mut url = url.to_owned();
    for remaining in (0..=redirects).rev() {
        let parsed = crate::conn::HttpUrl::parse(&url)
            .map_err(|error| format!("invalid URL: {url}: {error}"))?;
        let mut stream = if let Some(path) = socket {
            socket_stream(path).map_err(|error| format!("failed to dial to {url}: {error}"))?
        } else {
            let tcp = tcp_stream(&parsed.host, parsed.port)
                .map_err(|error| format!("failed to dial to {url}: {error}"))?;
            if parsed.tls {
                let config = ferrox_core::tls::TlsConfig {
                    server_name: parsed.host.clone(),
                    alpn: vec![b"http/1.1".to_vec()].into(),
                    roots: crate::quic::system_roots(),
                    resumption: true,
                    ..Default::default()
                };
                match ferrox_core::tls::RustlsProvider::connect(&config, tcp) {
                    Ok(tls) => Box::new(tls) as Box<dyn ReadWrite>,
                    Err(error) => return Err(format!("failed to dial to {url}: {error}")),
                }
            } else {
                Box::new(tcp) as Box<dyn ReadWrite>
            }
        };
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: ferrox-app\r\nAccept-Encoding: gzip\r\n",
            parsed.path, parsed.authority
        );
        if let Some(userinfo) = &parsed.userinfo {
            use base64::Engine as _;
            request.push_str("Authorization: Basic ");
            request.push_str(&base64::engine::general_purpose::STANDARD.encode(userinfo));
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|error| format!("failed to dial to {url}: {error}"))?;
        let (status, headers, body) = read_http_head(&mut *stream)?;
        if status == 200 {
            return read_http_body(&mut *stream, body, &headers);
        }
        let location = headers
            .iter()
            .find(|(name, _)| name == "location")
            .map(|(_, value)| value.as_str());
        if (300..400).contains(&status) {
            if let Some(location) = location {
                if remaining == 0 {
                    return Err("stopped after 10 redirects".to_owned());
                }
                url = redirect_location(&parsed, location);
                continue;
            }
        }
        return Err(format!("unexpected HTTP status code: {status}"));
    }
    Err("stopped after 10 redirects".to_owned())
}

fn redirect_location(base: &crate::conn::HttpUrl, location: &str) -> String {
    let location = location.trim();
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_owned();
    }
    let scheme = if base.tls { "https" } else { "http" };
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    if location.starts_with('/') {
        return format!("{scheme}://{}{location}", base.authority);
    }
    let directory = match base.path.rfind('/') {
        Some(0) | None => "",
        Some(at) => &base.path[..at],
    };
    format!("{scheme}://{}{directory}/{location}", base.authority)
}

fn tcp_stream(host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs as _;
    let mut last = None;
    for address in (host, port).to_socket_addrs()? {
        match std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(30)) {
            Ok(stream) => {
                stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no address resolved")))
}

#[cfg(unix)]
fn socket_stream(path: &str) -> std::io::Result<Box<dyn ReadWrite>> {
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        if let Some(name) = path.strip_prefix("@@") {
            let mut padded = vec![0u8; 107];
            let raw = name.as_bytes();
            let len = raw.len().min(padded.len());
            padded[..len].copy_from_slice(&raw[..len]);
            let address = std::os::linux::net::SocketAddr::from_abstract_name(&padded)?;
            return finish_socket(UnixStream::connect_addr(&address)?);
        }
        if let Some(name) = path.strip_prefix('@') {
            let address = std::os::linux::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            return finish_socket(UnixStream::connect_addr(&address)?);
        }
    }
    finish_socket(UnixStream::connect(path)?)
}

#[cfg(unix)]
fn finish_socket(stream: std::os::unix::net::UnixStream) -> std::io::Result<Box<dyn ReadWrite>> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
fn socket_stream(path: &str) -> std::io::Result<Box<dyn ReadWrite>> {
    Err(std::io::Error::other(format!(
        "unix socket `{path}` is not supported on this platform"
    )))
}

type HttpHead = (u16, Vec<(String, String)>, Vec<u8>);

fn read_http_head(stream: &mut dyn ReadWrite) -> Result<HttpHead, String> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("failed to read HTTP response: {error}"))?;
        if read == 0 {
            return Err("failed to read HTTP response: unexpected end of stream".to_owned());
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&raw[..at])
                .map_err(|error| format!("failed to read HTTP response: {error}"))?;
            let mut lines = head.split("\r\n");
            let status = lines
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or_else(|| "failed to read HTTP response: bad status line".to_owned())?;
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
                .collect();
            return Ok((status, headers, raw[at + 4..].to_vec()));
        }
        if raw.len() > 1 << 20 {
            return Err("failed to read HTTP response: headers too large".to_owned());
        }
    }
}

fn read_http_body(
    stream: &mut dyn ReadWrite,
    mut body: Vec<u8>,
    headers: &[(String, String)],
) -> Result<Vec<u8>, String> {
    stream
        .read_to_end(&mut body)
        .map_err(|error| format!("failed to read HTTP response: {error}"))?;
    let header = |name: &str| {
        headers
            .iter()
            .find(|(have, _)| have == name)
            .map(|(_, value)| value.as_str())
    };
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        body = decode_chunked(&body)?;
    } else if let Some(length) = header("content-length") {
        let length = length
            .parse::<usize>()
            .map_err(|error| format!("failed to read HTTP response: {error}"))?;
        if body.len() < length {
            return Err("failed to read HTTP response: unexpected end of stream".to_owned());
        }
        body.truncate(length);
    }
    if header("content-encoding").is_some_and(|value| value.eq_ignore_ascii_case("gzip")) {
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(
            &mut flate2::read::GzDecoder::new(body.as_slice()),
            &mut decoded,
        )
        .map_err(|error| format!("failed to read HTTP response: {error}"))?;
        return Ok(decoded);
    }
    Ok(body)
}

fn decode_chunked(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let end = bytes[at..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "failed to read HTTP response: incomplete chunk".to_owned())?;
        let line = std::str::from_utf8(&bytes[at..at + end])
            .map_err(|error| format!("failed to read HTTP response: {error}"))?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or(line).trim(), 16)
            .map_err(|error| format!("failed to read HTTP response: {error}"))?;
        at += end + 2;
        if size == 0 {
            break;
        }
        let next = at
            .checked_add(size + 2)
            .filter(|next| *next <= bytes.len())
            .ok_or_else(|| "failed to read HTTP response: incomplete chunk".to_owned())?;
        out.extend_from_slice(&bytes[at..at + size]);
        at = next;
    }
    Ok(out)
}

/// The JSON stream a YAML or TOML spelling feeds to the same handler builder.
fn config_text(bytes: &[u8], format: SourceFormat) -> Result<std::borrow::Cow<'_, str>, String> {
    match format {
        SourceFormat::Yaml => {
            let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
            let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(text)
                .map_err(|error| format!("failed to convert yaml to json: {error}"))?;
            let mut out = String::new();
            crate::json::write(&yaml_json(&value)?, &mut out);
            Ok(std::borrow::Cow::Owned(out))
        }
        SourceFormat::Toml => {
            let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
            let value: toml::Value = toml::from_str(text)
                .map_err(|error| format!("failed to convert toml to map: {error}"))?;
            let mut out = String::new();
            crate::json::write(&toml_json(&value)?, &mut out);
            Ok(std::borrow::Cow::Owned(out))
        }
        SourceFormat::Json => Ok(std::borrow::Cow::Borrowed(
            std::str::from_utf8(bytes).map_err(|error| error.to_string())?,
        )),
        SourceFormat::Jsonc => Ok(crate::json::strip_jsonc(
            std::str::from_utf8(bytes).map_err(|error| error.to_string())?,
        )),
        SourceFormat::Protobuf => Err("protobuf is not JSON".to_owned()),
    }
}

fn yaml_mapping(map: &serde_yaml_ng::Mapping) -> Result<Vec<(String, crate::json::Json)>, String> {
    let mut explicit = Vec::new();
    let mut merge_values = Vec::new();
    for (key, value) in map {
        let serde_yaml_ng::Value::String(key) = key else {
            return Err(format!(
                "failed to convert yaml to json: map key {key:?} is not a string"
            ));
        };
        if key == "<<" {
            merge_values.push(value);
        } else {
            explicit.push((key.clone(), yaml_json(value)?));
        }
    }
    let mut inherited: Vec<(String, crate::json::Json)> = Vec::new();
    for value in merge_values {
        for source in yaml_merge_sources(value)? {
            for (key, value) in source {
                if !explicit.iter().any(|(have, _)| have == &key)
                    && !inherited.iter().any(|(have, _)| have == &key)
                {
                    inherited.push((key, value));
                }
            }
        }
    }
    explicit.extend(inherited);
    explicit.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(explicit)
}

fn yaml_merge_sources(
    value: &serde_yaml_ng::Value,
) -> Result<Vec<Vec<(String, crate::json::Json)>>, String> {
    match value {
        serde_yaml_ng::Value::Mapping(map) => Ok(vec![yaml_mapping(map)?]),
        serde_yaml_ng::Value::Sequence(items) => items
            .iter()
            .map(|item| match item {
                serde_yaml_ng::Value::Mapping(map) => yaml_mapping(map),
                _ => Err("failed to convert yaml to json: merge value is not a mapping".to_owned()),
            })
            .collect(),
        _ => Err("failed to convert yaml to json: merge value is not a mapping".to_owned()),
    }
}

#[allow(clippy::cast_precision_loss)]
fn yaml_json(value: &serde_yaml_ng::Value) -> Result<crate::json::Json, String> {
    use crate::json::Json;
    Ok(match value {
        serde_yaml_ng::Value::Null => Json::Null,
        serde_yaml_ng::Value::Bool(value) => Json::Bool(*value),
        serde_yaml_ng::Value::Number(number) => {
            let number = number
                .as_i64()
                .map(|value| value as f64)
                .or_else(|| number.as_u64().map(|value| value as f64))
                .or_else(|| number.as_f64())
                .filter(|value| value.is_finite())
                .ok_or_else(|| {
                    format!("failed to convert yaml to json: unsupported number {number:?}")
                })?;
            Json::Num(number)
        }
        serde_yaml_ng::Value::String(value) => Json::Str(value.clone()),
        serde_yaml_ng::Value::Sequence(items) => {
            Json::Arr(items.iter().map(yaml_json).collect::<Result<_, _>>()?)
        }
        serde_yaml_ng::Value::Mapping(map) => Json::Obj(yaml_mapping(map)?),
        serde_yaml_ng::Value::Tagged(tagged) => yaml_json(&tagged.value)?,
    })
}

#[allow(clippy::cast_precision_loss)]
fn toml_json(value: &toml::Value) -> Result<crate::json::Json, String> {
    use crate::json::Json;
    Ok(match value {
        toml::Value::String(value) => Json::Str(value.clone()),
        toml::Value::Integer(value) => Json::Num(*value as f64),
        toml::Value::Float(value) if value.is_finite() => Json::Num(*value),
        toml::Value::Float(value) => {
            return Err(format!(
                "failed to convert toml to map: unsupported number {value}"
            ));
        }
        toml::Value::Boolean(value) => Json::Bool(*value),
        toml::Value::Datetime(value) => Json::Str(value.to_string()),
        toml::Value::Array(items) => {
            Json::Arr(items.iter().map(toml_json).collect::<Result<_, _>>()?)
        }
        toml::Value::Table(table) => Json::Obj(
            table
                .iter()
                .map(|(key, value)| Ok((key.clone(), toml_json(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn serve_source(label: &str, bytes: &[u8], format: SourceFormat) -> ! {
    if let SourceFormat::Protobuf = format {
        proxy::serve_protobuf(label, bytes, test_only());
    }
    let body = config_text(bytes, format)
        .unwrap_or_else(|error| proxy::exit(&format!("bad config {label}: {error}")));
    proxy::serve_json(label, &body, test_only())
}

#[cfg(test)]
mod tests {
    #[test]
    fn shadowsocks_server_password_shape() {
        let root = crate::json::parse(
            r#"{"inbounds": [{"protocol": "shadowsocks", "settings": {"method": "aes-256-gcm",
            "password": "an-example-shared-password"}}]}"#,
        )
        .expect("parses");
        let inbound = &root
            .get("inbounds")
            .expect("inbounds")
            .as_arr()
            .expect("array")[0];
        assert_eq!(
            crate::proxy::inbound_ss_password(inbound),
            "an-example-shared-password"
        );
    }

    #[test]
    fn brief_link_checks() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#x",
        )
        .expect("parses");
        assert!(link.is_first_method());
    }

    #[test]
    fn both_out_of_band_consents_parse_in_either_order() {
        let mk = |args: [&str; 3]| {
            let mut it = args.iter().map(|s| (*s).to_owned());
            crate::link_and_opt_in(&mut it)
        };
        // A bare link carries neither consent.
        let (_, opt) = crate::link_and_opt_in(&mut ["vless://x".to_owned()].into_iter());
        assert!(!opt.unsafe_fingerprint() && !opt.plaintext_to_public());
        // Both flags flip their own consent and leave the other off, before or after the link.
        for (a, b) in [
            ("--allow-unsafe-fp", "--allow-plaintext-public"),
            ("--allow-plaintext-public", "--allow-unsafe-fp"),
        ] {
            let (link, opt) = mk(["vless://x", a, b]);
            assert_eq!(link, "vless://x");
            assert!(opt.unsafe_fingerprint() && opt.plaintext_to_public());
        }
    }

    /// The window reaches across the crate boundary: what an app test allocates is counted by core's allocator, so a count taken here measures the app.
    #[test]
    fn a_count_taken_here_sees_what_the_app_allocates() {
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let buffer = vec![0u8; 64];
            std::hint::black_box(&buffer);
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (1, 64, 1),
            "this test binary is not running on the allocator whose window `measure` opens"
        );
    }
}
