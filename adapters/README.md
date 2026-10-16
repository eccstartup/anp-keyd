# v2 client and existing ANP SDK connector

Node 18+ imports `KeydV2Client` from `keyd-v2.mjs`. The administrator supplies the
service config, grant and exact key handle. The Rust CLI authenticates the daemon.
Persist request IDs with their payload before calling `sign`; on uncertain
transport outcomes query `status` with that ID. Do not auto-generate another ID.
`fetch` sends only the daemon's canonical URL, original body and returned headers,
with manual redirects. There is no password, raw signing, lifecycle, or downgrade.

For the existing `@connectx-sdk/core` API:

```js
import { createConfig, signRequest, subjectOf } from '@connectx-sdk/core'
import { KeydV2Client, keydV2Connector } from './keyd-v2.mjs'
const client = new KeydV2Client()
const connector = keydV2Connector({ client, grant_id, key_id, subjectOf,
  requestId: req => durableRequestIdForThisExactPayload(req) })
const config = createConfig([connector])
const signed = await signRequest(config, connector.id, {
  method: 'POST', url: canonicalUrl, nonce: serverNonce,
})
```

Supply a stable request-ID function backed by your durable operation state.
The connector rejects successor/lifecycle operations. Registration challenge
proofs go through a distinct trusted management client. Existing SDK transport
must use canonical targets and disable redirects; the connector refuses a
noncanonical target after signing and requires querying the original ID.

`test-sdk.mjs SDK_DIST GRANT KEY REQUEST_ID` is the live Linux acceptance driver;
it runs the existing SDK's `createConfig` and `signRequest` under an Agent UID,
verifies same-ID result reuse, and prints a request for the real service harness.
External SDK sources are read-only test inputs, not vendored or modified here.
