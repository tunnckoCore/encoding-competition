# Claude vs. Codex / ChatGPT / GPT-5.6 Sol

The ultimate competition. Who will design and implement the best text format for encoding, decoding, and compacting structured data?

It's like a hackathon for our AIs.

A few months ago, I started with HBS3. It's included here too, along with its spec, conformance tests, and more. But it was designed for a different, specific use case: per-slot integrity/checksums, fault tolerance, streaming, typed schemas, validation, and massive deduplication. It's great, but its output is still big.

The raw minified JSON fixture is 271 KB. HBS3 outputs 191 KB.

Then I asked GPT-5.6 Sol in Ultra & Fast mode. I told it to be creative, bold, innovative - to be an inventor - and linked my HBS3 to see what's possible. It designed TGJ and DIA1.

TGJ's output is 115 KB. DIA1 is insane at 91.9 KB - it is a full LANGUAGE: an alphabet, a grammar, constructs, phrases, and contextual meanings. It uses emojis as the alphabet, and it can accept another alphabet to produce even smaller results. But it takes 1.9 seconds to encode.

How about real tokens comparison? We used the OpenAI tokenizer.

- HBS3 - 93.5k
- TOON - 87.2k
- JSON - 78.2k
- TGJ - 51.1k
- DIA1 - 43.8k

---

## The Idea

The idea is to have the smallest possible output while remaining a textual, non-binary encoding and decoding format.

Yes, the sizes are bytes, not characters.

The prompt:

```
lets think how can we create a tokenizer (encoding) format but also be possible to be decoded. The idea as less as possible size for structured data like JSON.

TOON is small but not that better. JSON is too verbose. CSV is not enough sometimes. Base64 and HEX are out of the question to begin with. I developed HBS3 (Ravel) and its spec is also in the repo called `hbs3-ravel-spec.md`.

After several months since HBS3, I just now realized that this compaction and encoding is pretty much what LLMs do with "tokens" and tokenizers. But don't want to go the full tokenization and deep learning and RL and embedding side of the stuff. I want it to be reasonable and implementable in TypeScript and/or Rust, and be the best format/encoding for smallest results while binary is out of scope.
```
