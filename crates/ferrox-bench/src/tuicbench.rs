use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

const PACKETS: usize = 65_536;

pub(crate) fn report() -> String {
    let address = ferrox_core::tuic::address_port("example.com", 443).expect("an address");
    let payload = [7u8; 1200];
    let mut frame = Vec::new();
    ferrox_core::tuic::encode_fragment(1, 2, 1, 0, &address, &payload, &mut frame);
    let start = Instant::now();
    for _ in 0..PACKETS {
        let _ = black_box(ferrox_core::tuic::parse_packet(black_box(&frame)));
    }
    let ns = start.elapsed().as_nanos() as f64 / PACKETS as f64;
    let mut out = String::new();
    let _ = writeln!(out, "## TUIC packet\n");
    let _ = writeln!(out, "| packets | ns/packet |");
    let _ = writeln!(out, "|---:|---:|");
    let _ = writeln!(out, "| {PACKETS} | {ns:.1} |");
    out
}
