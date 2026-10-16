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

`test-sdk.mjs SDK_DIST GRANT KEY REQUEST_ID RPC_REQUEST_ID` is the live Linux acceptance driver;
it runs the existing SDK's `createConfig` and `signRequest` under an Agent UID,
verifies same-ID result reuse, and prints a request for the real service harness.
External SDK sources are read-only test inputs, not vendored or modified here.

Compatibility boundary: anp-sdk signRequest produces an ANP-02 login body; awiki did-auth RPC requires a JSON-RPC envelope. The live acceptance verifies the former with the existing SDK verifier and nonce store, and uses the same v2 client with the actual JSON-RPC body for awiki. It does not rewrite already-signed bytes or claim a native SDK login endpoint exists on awiki.

The currently tested external SDK's `resolveVerificationKey` also compares the
selected hot key against the DID root fingerprint and rejects it. Its high-level
hot-key resolution is therefore outside the supported compatibility claim. The
acceptance separately verifies the root-signed document, requires authentication
authorization for the exact hot method, and passes that public key into the SDK's
HTTP verifier with expectedNonce and a one-time store. It reports the resolver
limitation explicitly; it never substitutes a root signing grant.
