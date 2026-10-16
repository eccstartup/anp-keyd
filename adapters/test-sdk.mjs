// Optional live acceptance: Node runs under a real independent Linux Agent UID.
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { KeydV2Client, keydV2Connector } from './keyd-v2.mjs'
const [sdkPath, grant_id, key_id, request_id] = process.argv.slice(2)
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
console.log(JSON.stringify(first))
