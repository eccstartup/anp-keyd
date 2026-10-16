// Optional live acceptance: Node runs under a real independent Linux Agent UID.
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { KeydV2Client, keydV2Connector } from './keyd-v2.mjs'
const [sdkPath, grant_id, key_id, request_id, rpc_request_id] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath))
const client = new KeydV2Client()
const connector = keydV2Connector({ client, grant_id, key_id, requestId: () => request_id, subjectOf: sdk.subjectOf })
const config = sdk.createConfig([connector])
const request = { method: 'POST', url: 'https://example.com/user-service/v1/did-auth/rpc', nonce: request_id,
  extraBody: { jsonrpc: '2.0', id: request_id, method: 'get_me', params: {} } }
const first = await sdk.signRequest(config, connector.id, request)
assert(first.keyid.includes('#http-'))
assert(first.headers['Signature'] || first.headers.signature)
const second = await sdk.signRequest(config, connector.id, request)
assert.deepEqual(second, first, 'persisted request ID must return identical headers and body')
const status = await client.status(request_id)
assert.equal(status.state, 'completed')
assert.equal((await client.grant(grant_id)).used_uses, 1)
await assert.rejects(connector.signRequest({ ...request, successorDid: 'did:wba:other.example' }), /management/)
sdk.verifyDidDocument(first.didDocument, first.did)
assert(first.didDocument.authentication.includes(first.keyid))
// The current external SDK resolver incorrectly binds every selected key to
// the DID's root fingerprint. Record that compatibility limit explicitly.
let sdkHotResolverSupported = true
try { await sdk.resolveVerificationKey(first.keyid, first.didDocument) }
catch (error) {
  if (error.code !== 'did_resolve_invalid_document' || !error.message.includes('fingerprint')) throw error
  sdkHotResolverSupported = false
}
const verification = {
  method: 'POST', path: '/user-service/v1/did-auth/rpc', authority: 'example.com', targetUri: request.url,
  headers: Object.fromEntries(Object.entries(first.headers).map(([k, v]) => [k.toLowerCase(), v])),
  body: first.body, key: sdk.decodeMultibaseKey(first.publicKey.publicKeyMultibase),
  expectedNonce: request_id, nonceStore: sdk.createNonceStore(),
}
assert(await sdk.verifyHttpMessageSignature(verification), 'existing SDK verifies v2 ANP-02 signature')
assert.equal(await sdk.verifyHttpMessageSignature(verification), false, 'SDK nonce store rejects replay')
// awiki's RPC accepts JSON-RPC bodies, not the SDK's ANP-02 login body.
// Use the v2 structured HTTP client with its actual service envelope.
assert(rpc_request_id, 'caller must persist a distinct ID for the RPC payload')
const body = JSON.stringify({ jsonrpc: '2.0', id: rpc_request_id, method: 'get_me', params: {} })
const rpc = await client.sign({ grant_id, request_id: rpc_request_id, method: 'POST', url: request.url,
  headers: { 'content-type': 'application/json' }, body, nonce: rpc_request_id })
console.log(JSON.stringify({ body, headers: rpc.headers, sdkProtocolVerified: true, sdkHotResolverSupported }))
