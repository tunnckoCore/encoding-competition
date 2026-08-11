# Claude VS. Codex/ChatGPT/GPT-5.6 Sol

The ultimate competition. Who will design and implement the best encoding/decoding/compacting text format.

It's like a hackaton, for our AIs.

I started few months ago with HBS3, it's included here too and there is spec, conformance tests and etc. But it had different features designed for specific case - it has per-slot integrity/checksum, fault-tolerant, streaming, typed schema, validation, massive deduplication. It's great, but still big in output size.

The raw minified JSON fixture is 271kb. HBS3 outputs 191kb.

Then i asked GPT-5.6 Sol Ultra Fast mode. Told it to be creative, bold, innovative, inventor, and linked my HBS3 to see what's possible. It designed TGJ and DIA1.

The TGJ size is 115kb. The DIA1 is insane, at 91.9kb - it is a full LANGUAGE - an alphabet, a grammer, constructs, phrases, contextual meanings. And it uses emojis as the alphabet. And it can accept another alphabet and output even smaller results. But it takes 1.9s to encode.

---

## The Idea

The idea is to have the smallest possible output. To be an encoding and decoding format that is ASCII/text based only.

Yes, the sizes are bytes, not characters.

The prompt:

```
lets think how can we create a tokenizer (encoding) format but also be possible to be decoded. The idea as less as possible size for structured data like JSON.

TOON is small but not that better. JSON is too verbose. CSV is not enough sometimes. Base64 and HEX are out of the question to begin with. I developed HBS3 (Ravel) and its spec is also in the repo called `hbs3-ravel-spec.md`.

After several months since HBS3, I just now realized that this compaction and encoding is pretty much what LLMs do with "tokens" and tokenizers. But don't want to go the full tokenization and deep learning and RL and embedding side of the stuff. I want it to be reasonable and implementable in TypeScript and/or Rust, and be the best format/encoding for smallest results while binary is out of scope.
```
