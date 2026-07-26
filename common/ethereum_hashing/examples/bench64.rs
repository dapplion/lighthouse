fn main() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let mut acc = ethereum_hashing::hash32_concat(&a, &b);
    let n = 4_000_000u32;
    let t = std::time::Instant::now();
    for _ in 0..n {
        acc = ethereum_hashing::hash32_concat(&acc, &b);
    }
    let elapsed = t.elapsed();
    println!(
        "{:.1} ns/hash ({acc:02x?})",
        elapsed.as_nanos() as f64 / n as f64
    );
}
