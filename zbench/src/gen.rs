//! Deterministic inputs that look like MongoDB wire messages: an OP_MSG reply with a cursor
//! batch of BSON documents.

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
}

const WORDS: &[&str] = &[
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
    "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
    "uniform", "victor", "whiskey", "xray", "yankee", "zulu", "storage", "engine", "index",
    "cursor", "document", "collection", "replica", "primary", "secondary", "shard", "balance",
    "customer", "order", "invoice", "payment", "shipping", "pending", "complete", "cancelled",
    "Berlin", "Hamburg", "Munich", "Cologne", "Frankfurt", "Stuttgart", "Leipzig", "Dresden",
];
const STATUS: &[&str] = &["pending", "shipped", "delivered", "cancelled", "returned"];

fn cstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}
fn el_str(out: &mut Vec<u8>, name: &str, v: &str) {
    out.push(0x02);
    cstr(out, name);
    out.extend_from_slice(&(v.len() as i32 + 1).to_le_bytes());
    cstr(out, v);
}
fn el_i32(out: &mut Vec<u8>, name: &str, v: i32) {
    out.push(0x10);
    cstr(out, name);
    out.extend_from_slice(&v.to_le_bytes());
}
fn el_i64(out: &mut Vec<u8>, name: &str, v: i64) {
    out.push(0x12);
    cstr(out, name);
    out.extend_from_slice(&v.to_le_bytes());
}
fn el_f64(out: &mut Vec<u8>, name: &str, v: f64) {
    out.push(0x01);
    cstr(out, name);
    out.extend_from_slice(&v.to_le_bytes());
}
fn el_date(out: &mut Vec<u8>, name: &str, v: i64) {
    out.push(0x09);
    cstr(out, name);
    out.extend_from_slice(&v.to_le_bytes());
}
fn el_bool(out: &mut Vec<u8>, name: &str, v: bool) {
    out.push(0x08);
    cstr(out, name);
    out.push(v as u8);
}
fn el_oid(out: &mut Vec<u8>, name: &str, rng: &mut Rng, n: u32) {
    out.push(0x07);
    cstr(out, name);
    out.extend_from_slice(&0x6741_2a00u32.wrapping_add(n / 7).to_be_bytes());
    out.extend_from_slice(&[0x5a, 0x1f, 0xc3, 0x9e, 0x77]);
    let c = (rng.0 as u32 & 0xff_0000) | n;
    out.extend_from_slice(&c.to_be_bytes()[1..]);
}
/// Writes a sub-document (type 3) or array (type 4) with a length prefix around `f`.
fn el_doc(out: &mut Vec<u8>, ty: u8, name: &str, f: impl FnOnce(&mut Vec<u8>)) {
    out.push(ty);
    cstr(out, name);
    doc(out, f);
}
fn doc(out: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[0; 4]);
    f(out);
    out.push(0);
    let len = (out.len() - at) as i32;
    out[at..at + 4].copy_from_slice(&len.to_le_bytes());
}
fn words(rng: &mut Rng, n: u64) -> String {
    let mut s = String::new();
    for i in 0..n {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(WORDS[rng.below(WORDS.len() as u64) as usize]);
    }
    s
}

fn order(out: &mut Vec<u8>, rng: &mut Rng, n: u32) {
    doc(out, |out| {
        el_oid(out, "_id", rng, n);
        el_i32(out, "orderId", 100_000 + n as i32);
        el_i64(out, "customerId", rng.below(5_000_000) as i64);
        el_str(out, "status", STATUS[rng.below(STATUS.len() as u64) as usize]);
        el_date(out, "createdAt", 1_760_000_000_000 + rng.below(40_000_000_000) as i64);
        el_f64(out, "total", rng.below(1_000_000) as f64 / 100.0);
        el_bool(out, "priority", rng.below(5) == 0);
        el_str(out, "email", &format!("{}.{}{}@example.com", WORDS[rng.below(26) as usize], WORDS[rng.below(26) as usize], rng.below(1000)));
        el_doc(out, 3, "address", |out| {
            el_str(out, "street", &format!("{} street {}", WORDS[rng.below(26) as usize], rng.below(200)));
            el_str(out, "city", WORDS[44 + rng.below(8) as usize]);
            el_str(out, "zip", &format!("{:05}", rng.below(100_000)));
        });
        el_doc(out, 4, "items", |out| {
            for i in 0..1 + rng.below(3) {
                el_doc(out, 3, &i.to_string(), |out| {
                    el_str(out, "sku", &format!("SKU-{:06}", rng.below(1_000_000)));
                    el_i32(out, "qty", 1 + rng.below(9) as i32);
                    el_f64(out, "price", rng.below(100_000) as f64 / 100.0);
                });
            }
        });
        let n_words = 3 + rng.below(8);
        el_str(out, "note", &words(rng, n_words));
    });
}

/// An OP_MSG reply `{cursor: {firstBatch: [docs...], id, ns}, ok: 1}` with its 16-byte header
/// and flag bits, as it goes into the wire compressor (which sees it from the flag bits on).
pub fn find_reply(docs: u32, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out = vec![0u8; 4]; // flag bits
    out.push(0); // section kind 0
    doc(&mut out, |out| {
        el_doc(out, 3, "cursor", |out| {
            el_doc(out, 4, "firstBatch", |out| {
                for i in 0..docs {
                    out.push(3);
                    cstr(out, &i.to_string());
                    order(out, &mut rng, i);
                }
            });
            el_i64(out, "id", 0);
            el_str(out, "ns", "shop.orders");
        });
        el_f64(out, "ok", 1.0);
    });
    out
}

/// A small command: an insert of one tiny document, about 100 bytes.
pub fn small_command(seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out = vec![0u8; 4];
    out.push(0);
    doc(&mut out, |out| {
        el_str(out, "insert", "orders");
        el_bool(out, "ordered", true);
        el_str(out, "$db", "shop");
        el_doc(out, 4, "documents", |out| {
            el_doc(out, 3, "0", |out| {
                el_oid(out, "_id", &mut rng, 1);
                el_i32(out, "qty", 3);
            });
        });
    });
    out
}
