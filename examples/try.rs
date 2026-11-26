//! Decodes a file with c14zz-zstd and the C library and says what each makes of it.
fn main() {
    let data = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    println!("header: {:?}", c14zz_zstd::FrameHeader::read(&data));
    match c14zz_zstd::decompress(&data) {
        Ok(v) => println!("c14zz-zstd: {} bytes", v.len()),
        Err(e) => println!("c14zz-zstd: {e}"),
    }
    match zstd::bulk::decompress(&data, 8 << 20) {
        Ok(v) => println!("C: {} bytes", v.len()),
        Err(e) => println!("C: {e}"),
    }
}
