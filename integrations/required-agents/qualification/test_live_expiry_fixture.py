"""Synthetic controls for the fetch-hold fixture, never real-host acceptance."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/acceptance/expire-during-host.mjs"


class LiveExpiryFixtureTests(unittest.TestCase):
    def exercise(self, mode):
        self.assertIsNotNone(shutil.which("node"), "Node is required for expiry fixture controls")
        with tempfile.TemporaryDirectory(prefix="chio-expiry-control-") as directory:
            root = Path(directory)
            now = int(time.time())
            expiry = now - 1 if mode == "missed-window" else now + 1
            config = {"execution": {"endpoint": "http://127.0.0.1:12345", "capabilityId": "fixture-cap",
                       "subjectKey": "fixture-caller", "sessionId": "fixture-session",
                       "bearerToken": "synthetic-fixture-only"},
                      "sessionCredential": {"expiresAt": expiry, "sessionId": "fixture-session"}}
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config))
            first = {"path": "/workspace/fixture.txt", "content": "first"}
            second = {**first, "content": "second"}
            binding = {"gatewayConfig": str(config_path), "configurationSha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                       "capability": {"id": "fixture-cap", "subject": "fixture-caller", "issued_at": expiry - 2, "expires_at": expiry},
                       "sessionCredential": config["sessionCredential"],
                       "nativeRequests": [{"tool": "write_file", "arguments": first}, {"tool": "write_file", "arguments": second}]}
            if mode == "wrong-caller":
                binding["capability"]["subject"] = "different-caller"
            if mode.startswith("gateway-"):
                binding["host"] = "openclaw"
            binding_path = root / "binding.json"
            binding_path.write_text(json.dumps(binding))
            log = root / "events.jsonl"
            script = root / "control.mjs"
            script.write_text("""import {pathToFileURL} from 'node:url';
import {readFileSync} from 'node:fs';
import {createServer,request as httpRequest} from 'node:http';
const [helper,mode,bindingPath]=process.argv.slice(2);
const binding=JSON.parse(readFileSync(bindingPath,'utf8'));
// Only these synthetic controls use a controlled clock. Native qualification
// uses the real process clock and the independently read issued capability.
let clock=binding.capability.expires_at*1000+(mode==='missed-window'?1:-500);
Date.now=()=>clock;
let forwarded=0;const responseStatuses=[];
globalThis.fetch=async function(input,init){
 forwarded++;
 if(init.signal.aborted)throw Error('mock transport observed aborted signal');
 return forwarded===1||mode==='server-allows'?new Response('{"actual":"allowed"}',{status:200}):new Response('invalid, expired, or revoked session credential',{status:401,headers:{'www-authenticate':'Bearer'}});
};
let error,observedGatewayBody;
try{
 await import(pathToFileURL(helper).href);
 if(mode.startsWith('gateway-')){
  const server=createServer(async(req,res)=>{const chunks=[];for await(const chunk of req)chunks.push(chunk);observedGatewayBody=Buffer.concat(chunks).toString();res.setHeader('mcp-session-id',mode==='gateway-invalid-session'?'invalid':'A'.repeat(43));res.end('{}');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  await new Promise((resolve,reject)=>{const req=httpRequest({hostname:'127.0.0.1',port:server.address().port,path:mode==='gateway-wrong-path'?'/other':'/mcp',method:'POST',headers:{authorization:'Bearer synthetic-session-observer-secret'}},res=>{res.resume();res.on('end',resolve);});req.on('error',reject);req.end('unchanged initialize request body');});
  await new Promise(resolve=>server.close(resolve));
 }
 for(let index=0;index<2;index++){
  const controller=new AbortController();
  if(index===1&&mode==='aborted')setTimeout(()=>controller.abort(),10);
  if(index===1)setTimeout(()=>{clock=binding.capability.expires_at*1000+1001;},50);
  const args=binding.nativeRequests[index].arguments;
  const body=JSON.stringify({jsonrpc:'2.0',id:index+1,method:'tools/call',params:{name:'write_file',arguments:{content:args.content,path:args.path},_meta:{chioRequestId:'fixture-request-'+index}}});
  const headers={authorization:'Bearer synthetic-fixture-only','MCP-Session-Id':mode==='wrong-session'?'different-session':'fixture-session','MCP-Protocol-Version':'2025-11-25'};
  if(index===1&&mode==='mutated-header')setTimeout(()=>{headers['MCP-Session-Id']='different-session';},10);
  const response=await globalThis.fetch('http://127.0.0.1:12345/mcp',{method:'POST',headers,body,signal:controller.signal});
  responseStatuses.push(response.status);
 }
}catch(value){error=value.message;}
console.log(JSON.stringify({forwarded,responseStatuses,error,observedGatewayBody}));
""")
            env = {key: value for key, value in os.environ.items() if key != "NODE_OPTIONS"}
            env.update(CHIO_TEST_GATEWAY_CONFIG=str(config_path), CHIO_INFLIGHT_EXPIRY_BINDING=str(binding_path), CHIO_INFLIGHT_EXPIRY_LOG=str(log))
            result = subprocess.run(["node", str(script), str(HELPER), mode, str(binding_path)], capture_output=True, text=True, env=env, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            if mode.startswith("gateway-"):
                value['gatewaySessions'] = [json.loads(line) for line in (root / 'openclaw-gateway-session.jsonl').read_text().splitlines()]
            return value, events

    def test_actual_response_is_preserved_after_expiry_hold(self):
        value, events = self.exercise("expired-response")
        self.assertEqual(value, {"forwarded": 2, "responseStatuses": [200, 401]})
        self.assertEqual([event["event"] for event in events], ["native-request", "kernel-response", "native-request", "released-to-kernel", "kernel-response"])
        self.assertLess(events[2]["heldAtMs"], events[2]["capabilityExpiresAt"] * 1000)
        self.assertGreater(events[3]["releasedAtMs"], events[2]["capabilityExpiresAt"] * 1000)
        self.assertFalse(events[4]["signalAborted"])
        self.assertEqual(events[2]["requestBodySha256"], events[4]["requestBodySha256"])

    def test_fixture_does_not_fabricate_a_server_denial(self):
        value, events = self.exercise("server-allows")
        self.assertEqual(value["responseStatuses"], [200, 200])
        self.assertEqual(events[-1]["status"], 200)
        self.assertEqual(events[-1]["body"], '{"actual":"allowed"}')

    def test_aborted_original_signal_never_reaches_transport(self):
        value, events = self.exercise("aborted")
        self.assertEqual(value["forwarded"], 1)
        self.assertIn("Client aborted", value["error"])
        self.assertEqual(events[-1]["event"], "client-aborted")

    def test_wrong_caller_fails_before_any_fetch(self):
        value, events = self.exercise("wrong-caller")
        self.assertEqual(value["forwarded"], 0)
        self.assertIn("authority binding differs", value["error"])
        self.assertEqual(events, [])

    def test_missed_live_window_fails_before_any_fetch(self):
        value, _ = self.exercise("missed-window")
        self.assertEqual(value["forwarded"], 0)
        self.assertIn("missed its valid authority window", value["error"])

    def test_wrong_actual_session_header_fails_before_transport(self):
        value, _ = self.exercise("wrong-session")
        self.assertEqual(value["forwarded"], 0)
        self.assertIn("Actual native request differs", value["error"])

    def test_mutated_header_during_hold_never_reaches_transport(self):
        value, _ = self.exercise("mutated-header")
        self.assertEqual(value["forwarded"], 1)
        self.assertIn("changed during hold", value["error"])

    def test_observes_actual_http_session_without_consuming_body_or_exporting_bearer(self):
        value, _ = self.exercise('gateway-session')
        self.assertEqual(value['observedGatewayBody'], 'unchanged initialize request body')
        self.assertEqual(len(value['gatewaySessions']), 1)
        observed = value['gatewaySessions'][0]
        self.assertEqual(observed['sessionId'], 'A' * 43)
        self.assertEqual(observed['event'], 'gateway-http-initialized')
        self.assertNotIn('authorization', json.dumps(observed))
        self.assertNotIn('synthetic-session-observer-secret', json.dumps(observed))

    def test_unrelated_http_path_or_invalid_session_does_not_become_identity_evidence(self):
        for mode in ['gateway-wrong-path', 'gateway-invalid-session']:
            with self.subTest(mode=mode):
                value, _ = self.exercise(mode)
                self.assertEqual(value['gatewaySessions'], [])


if __name__ == "__main__":
    unittest.main()
