# rainbow

This repository contains a toy implementation of [rainbow tables](https://en.wikipedia.org/wiki/Rainbow_table),
including a small command-line interface for generating and searching through them. Functionality is fairly limited:

- Only supports MD5, which is [cryptographically broken][cb] anyway
- Basic reduction function family: add reduction index, take bottom bits, convert to ASCII alphanumeric
- Not very optimized (although it is multi-threaded, thanks to [rayon][mt])
- Plaintext length is hard-coded to 5 or 6 bytes
- Plaintext content is hard-coded to `a-zA-Z0-9_.`

# Implementation

References I found helpful are linked below, and [src/lib.rs](./src/lib.rs) is commented in some detail.

# Example

A rainbow table for 5-byte plaintexts, composed of 50000 chains of length 50000, is included at [data/50000_50000_5.table](./data/50000_50000_5.table).

This table was generated with:

```bash
$ cargo run --release -- create --chain-count 50000 --chain-length 50000 --pass-length 5 --path data/50000_50000_5.table
```

And can be used for lookup with:

```bash
$ echo -n "F0O0O" > plaintext.txt
$ md5 -q plaintext.txt
ebae3e4596d2c78e96d91c4c57f63366
$ cargo run --release -- search --path data/50000_50000_5.table --pass-length 5 ebae3e4596d2c78e96d91c4c57f63366
F0O0O
```

Naively storing all pairs of passwords and hashes would take (5B/password + 16B/hash) * 64^5 ≈ 22GB.
The rainbow table only takes ~1MB of storage (although it doesn't provide perfect coverage).

# References

- https://en.wikipedia.org/wiki/Rainbow_table
- https://www.ionos.com/digitalguide/server/security/rainbow-tables/
- https://security.stackexchange.com/questions/379/what-are-rainbow-tables-and-how-are-they-used
- https://fasterthanli.me/series/tech-as-seen-on-tv/part-1
- https://crypto.stackexchange.com/questions/62757/how-to-prove-that-a-rainbow-table-is-complete
- https://crypto.stackexchange.com/questions/30789/whats-the-perfect-chain-length-number-of-chains-ratio-for-rainbow-tables
- https://project-rainbowcrack.com/index.htm
- https://ophcrack.sourceforge.io/

[cb]: https://www.kb.cert.org/vuls/id/836068
[mt]: https://github.com/rayon-rs/rayon
