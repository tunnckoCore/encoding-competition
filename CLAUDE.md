- always read the `~/skills/instructions.md`; DO NOT read it, if you know you already read it (eg. it's in the session).
- this repo is Vite-plus managed: always use `vp run ready` - it runs type checking, linting, formatting, testing, building; do not invent stuff. Scripts are managed by vite.config.ts
- always use conventional commits

## Git and Github

• git and gh are routed by gitswitch . Inspect the repository remote url:  
if it includes tunnckoCore use gitswitch switch tunnckoCore and if it  
includes olstenlarck use gitswitch switch olstenlarck .  
• Git transport is SSH-only - both auth and signing - and SSH commit/tag  
signing is required. Both GitHub accounts use distinct P-256 keys for  
authentication and signing.  
• For git/gh ops: never change a remote to HTTPS. Do NOT install/use an  
HTTPS credential helper, do NOT run gh auth setup-git ; do NOT migrate/copy
authentication state, or change GitHub authentication/protocol state unless
explicitly requested.

## Merge pull requests

• always squash merge pull requests.  
• never create a Merge pull request ... commit.  
• do not use a merge commit when the pull request can be squash merged.
