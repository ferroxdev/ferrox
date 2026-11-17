use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

const PACKETS: usize = 65_536;
const ROUNDS: usize = 9;

fn prefix_len(data: &[u8]) -> usize {
    match black_box(ferrox_core::tuic::parse_packet_prefix(data)) {
        Ok((_, used)) => used,
        Err(_) => 0,
    }
}

fn double_parse(data: &[u8]) -> usize {
    match black_box(ferrox_core::tuic::parse_packet_prefix(data)) {
        Ok((_, used)) => match black_box(ferrox_core::tuic::parse_packet(&data[..used])) {
            Ok(packet) => packet.payload.len(),
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

fn elapsed<R>(run: &mut impl FnMut(&[u8]) -> R, frame: &[u8]) -> f64 {
    let start = Instant::now();
    for _ in 0..PACKETS {
        let _ = black_box(run(black_box(frame)));
    }
    start.elapsed().as_nanos() as f64 / PACKETS as f64
}

fn measure<A, B>(
    mut first: impl FnMut(&[u8]) -> A,
    mut second: impl FnMut(&[u8]) -> B,
    frame: &[u8],
) -> (f64, f64) {
    let mut first_best = f64::MAX;
    let mut second_best = f64::MAX;
    for round in 0..ROUNDS {
        let (first_ns, second_ns) = if round % 2 == 0 {
            let first_ns = elapsed(&mut first, frame);
            (first_ns, elapsed(&mut second, frame))
        } else {
            let second_ns = elapsed(&mut second, frame);
            (elapsed(&mut first, frame), second_ns)
        };
        first_best = first_best.min(first_ns);
        second_best = second_best.min(second_ns);
    }
    (first_best, second_best)
}

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
    let (once, twice) = measure(prefix_len, double_parse, &frame);
    let mut out = String::new();
    let _ = writeln!(out, "## TUIC packet\n");
    let _ = writeln!(out, "| packets | ns/packet |");
    let _ = writeln!(out, "|---:|---:|");
    let _ = writeln!(out, "| {PACKETS} | {ns:.1} |");
    let _ = writeln!(out, "\n## TUIC stream packet\n");
    let _ = writeln!(out, "| path | ns/packet |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| one parse | {once:.1} |");
    let _ = writeln!(out, "| two parses | {twice:.1} |");
    let _ = writeln!(out, "| saved | {:.1} |", twice - once);
    out
}
