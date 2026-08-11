# Real prose corpus provenance

`real-prose-master.txt` is an unabridged extraction of the main prose body of Charles Darwin's scientific work _The Origin of Species by Means of Natural Selection_ (sixth London edition, with additions and corrections).

## Source

| Field                     | Value                                                                                                                                                                                                                                                                                                          |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Title                     | _The Origin of Species by Means of Natural Selection_                                                                                                                                                                                                                                                          |
| Author                    | Charles Darwin                                                                                                                                                                                                                                                                                                 |
| Project Gutenberg eBook   | No. 2009                                                                                                                                                                                                                                                                                                       |
| Plain-text source URL     | <https://www.gutenberg.org/cache/epub/2009/pg2009.txt>                                                                                                                                                                                                                                                         |
| Catalog URL               | <https://www.gutenberg.org/ebooks/2009>                                                                                                                                                                                                                                                                        |
| Public-domain status      | Project Gutenberg identifies this eBook as public domain in the USA. The downloaded distribution is made available under the Project Gutenberg License terms in its wrapper; that wrapper is not part of the corpus. Users outside the USA should verify the copyright law that applies in their jurisdiction. |
| Retrieval date            | 2026-08-11                                                                                                                                                                                                                                                                                                     |
| Downloaded source bytes   | 1,303,005                                                                                                                                                                                                                                                                                                      |
| Downloaded source SHA-256 | `27c02feed0b90e0163811a35a7565d03611dc1d3f86703d6bec4ae73d2d612b8`                                                                                                                                                                                                                                             |

The source snapshot was retrieved with:

```sh
wget -q 'https://www.gutenberg.org/cache/epub/2009/pg2009.txt' -O pg2009.txt
```

## Transformations

The downloaded file used CRLF line endings. CRLF was normalized to LF, then one contiguous section was selected: the line `ORIGIN OF SPECIES.` was included as the first line, and extraction stopped before `GLOSSARY OF THE PRINCIPAL SCIENTIFIC TERMS USED IN THE PRESENT VOLUME.*`. This retains the introduction and Chapters I–XV while excluding Project Gutenberg metadata and license boilerplate, the edition-selection note, front matter and contents, the glossary, and the index. No prose, spelling, punctuation, typography, wrapping, or internal whitespace was otherwise changed.

The transformation can be reproduced with:

```sh
perl -pe 's/\r\n/\n/g' pg2009.txt > pg2009-lf.txt
awk '
  /^ORIGIN OF SPECIES\.$/ { capture = 1 }
  capture && /^GLOSSARY OF THE PRINCIPAL SCIENTIFIC TERMS USED IN THE PRESENT VOLUME\.\*$/ { exit }
  capture { print }
' pg2009-lf.txt > real-prose-master.txt
```

## Master artifact

| Field        | Value                                                              |
| ------------ | ------------------------------------------------------------------ |
| File         | `real-prose-master.txt`                                            |
| Encoding     | UTF-8                                                              |
| Line endings | LF                                                                 |
| Exact bytes  | 1,152,273                                                          |
| Lines        | 18,224                                                             |
| SHA-256      | `29849054f41b85907245519c53957f7c6c72e2d71b0a78288604f773c1f06d16` |
