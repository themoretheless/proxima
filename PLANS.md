# Plans

What is next, and why in this order. Kept here so the list stops living in
chat logs.

## Done

- **Traffic archive.** Finished flows recorded to DuckDB, `POST
  /api/archive/query` and `GET /api/archive/stats` over them. Behind the
  off-by-default `archive` feature.
- **Rewrite rules.** Request and response headers set, replaced and removed;
  `--map-host` sends a host's traffic elsewhere. Edits land before the flow is
  recorded, and each change leaves a note on the flow.

## Next

**Order matters for the first three.** Map local, breakpoints and the rewrite
rules already shipped all live at the same point in `proxy/forward.rs`, where a
request is held before going upstream. Doing them out of order means touching
that code three times.

1. **Map local / mock.** Answer a matched request from a file or a literal
   body without going upstream. `RewriteRule` already finds the right requests;
   what is missing is an action that returns a response instead of forwarding
   one. A mocked flow has to be marked as mocked in the capture, for the same
   reason a rewritten one carries notes.
2. **Breakpoints.** Pause a request or response, hand it to the inspector, let
   it be edited, then release it. The largest of the three: it needs the
   interception point, a protocol for the pause over the event socket, and UI.
   Wants a timeout, since a paused request with nobody watching is a hung app.
3. **The UI pass.** One change, three things that all live in
   `inspector.rs`: filter controls over `FlowQuery` (which already takes
   search, hosts, methods and status ranges, so this is UI only), a statistics
   panel over `/api/archive`, and an editor for the rewrite rules. This is the
   largest gap today: two shipped features are reachable by curl and not by
   mouse.

Independent of the above, in no particular order:

- **Throttling.** Emulate 3G, EDGE and packet loss. Touches nothing else.
- **Body decoders.** protobuf and gRPC, msgpack, and JWT in an `Authorization`
  header. protobuf is common in iOS traffic and is unreadable in the inspector
  today.
- **HAR import.** Export exists; the other direction does not.
- **Reloading the archive into the inspector.** A restart currently starts with
  an empty list. Metadata survives in the archive but bodies do not, so a
  reloaded flow can never be complete, and the UI has to say which is which
  rather than pretend.

## Debts

Taken on deliberately, worth clearing.

- The archive file has no rotation and no size ceiling.
- Rewrite rules scoped to a host, method or path exist in `RewriteRule` but can
  only be built from code. The command line sets global rules only, on purpose;
  the API should expose the scoped ones.
- `config_from` returns a `Result`, so a malformed rewrite flag prints as
  `proxima: ...` rather than in clap's style. The message names the flag, but
  the formatting differs from the `--no-decrypt`/`--only` conflict.
