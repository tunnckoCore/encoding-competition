# Generated prose corpus

This corpus was generated on 2026-08-11 by ten concurrent Codex agents using the session's resolved `gpt-5.6-sol` model. Each agent was asked for 52,000-60,000 UTF-8 bytes of original, natural long-form prose in coherent paragraphs, restricted to ASCII and explicitly excluding Markdown headings, lists, code, tables, boilerplate, and repeated or templated sentences. Generation is nondeterministic, so the committed chunks are the authoritative source rather than an expectation that the prompts reproduce identical bytes.

The ten assigned subjects were field ecology and seasonal evidence; port-city history and archives; memory, testimony, and public knowledge; astronomy and instrument building; urban planning and civic infrastructure; cognition, language learning, and psychological inference; oceanography and research vessels; household economics and policy tradeoffs; art conservation and restoration ethics; and software maintenance, standards, and institutional change.

`generated-prose-master.txt` is assembled by taking the first paragraph from chunks 01-10 in order, then the second paragraph from every chunk, and continuing round-robin until all paragraphs are consumed. Paragraphs are separated by two LF bytes. This makes every prefix span multiple subjects instead of allowing the 50 KB sample to contain only one essay. The benchmark additionally normalizes both generated and real prose to LF with one physical line per paragraph before taking its nested 50,000, 100,000, 250,000, and 500,000-byte scaling samples.

| File | UTF-8 bytes | SHA-256 |
|---|---:|---|
| `chunk-01.txt` | 58,695 | `553ebb47e9ab20637070bdbc0acb12b4af64f7964a0b35d45ff8b407e5907b29` |
| `chunk-02.txt` | 55,197 | `f23bc981c7c8de2a76bdc20dfb7e74aede1f38c9bd1259e3908698aebc4041fe` |
| `chunk-03.txt` | 59,626 | `c0446d8350189205224e244bdf92699e688d1ac8634e7bf45660fdbf9dfbae2b` |
| `chunk-04.txt` | 57,298 | `f02cd8b80a0a380c322d3c80a5e83c5bfa0b90a46d9fbc198b5da5c715c6b38b` |
| `chunk-05.txt` | 59,955 | `9229155f1d3d2d88e77b46b0118403ff18103b3d8ea7fe4ca0cf6537bf75d238` |
| `chunk-06.txt` | 53,824 | `345ef8200e89b5193fbd4867e985bd11c16059e223a92520504803d09b9cd083` |
| `chunk-07.txt` | 55,252 | `771def78c3a8a0f3dc343398470ef1876d2a6e6a39178aad5af2193d90a7013a` |
| `chunk-08.txt` | 59,414 | `7dd37366238d5b930d57859c7a2b58e3ea24a6e7c8c1c388837fa4ab08b88aa0` |
| `chunk-09.txt` | 58,626 | `cfabfc2436f424b2b28153601c52d5ff1c1c9839f24465edd214f6c249ab3c38` |
| `chunk-10.txt` | 58,008 | `22822a7763beb77105f8f0bdb77e9408ab58fc065316882a5e3afda9e0d7b4c7` |
| `generated-prose-master.txt` | 575,904 | `1c2cc031cdcddb6537049c57f535b604007b94149c00a9605d5848d16baa0b89` |
