#!/usr/bin/env python3
"""Qualify restricted credentials against a real kernel and isolated Docker filesystem.

No host integration acceptance is implied. All state and resource volumes are
new, explicitly labeled, and retained for independent inspection.
"""
import argparse
import hashlib
import http.client
import http.server
import copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import cryptography
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


def relay(argv):
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    delayed = set()
    def incoming():
        for line in sys.stdin:
            try:
                message = json.loads(line)
                if message.get('params', {}).get('arguments', {}).get('path') == '/workspace/unknown.txt':
                    delayed.add(str(message.get('id')))
            except (ValueError, AttributeError):
                pass
            child.stdin.write(line)
            child.stdin.flush()
        child.stdin.close()
    threading.Thread(target=incoming, daemon=True).start()
    for line in child.stdout:
        try:
            if str(json.loads(line).get('id')) in delayed:
                time.sleep(float(os.environ.get("CHIO_CREDENTIAL_TEST_DELAY_SECONDS", "4")))
        except (ValueError, AttributeError):
            pass
        sys.stdout.write(line)
        sys.stdout.flush()
    return child.wait()


def canonical_test_json(value):
    """RFC8785-compatible restricted fixture subset; reject floats and non-ASCII keys."""
    def validate(item):
        if item is None or isinstance(item, (bool,str)): return
        if isinstance(item,int) and abs(item) <= 9007199254740991: return
        if isinstance(item,list):
            for child in item: validate(child)
            return
        if isinstance(item,dict) and all(isinstance(key,str) and key.isascii() for key in item):
            for child in item.values(): validate(child)
            return
        raise ValueError('fixture falls outside the supported canonical JSON subset')
    validate(value)
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical_test_json(value)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    runtime = Path(args.runtime).resolve()
    runtime.mkdir(mode=0o700, exist_ok=False)
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    binary = str(Path(args.binary).resolve(strict=True))
    identity = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    volume = 'chio-required-credentials-' + secrets.token_hex(6)
    audit_volume = volume + '-audit'
    operator, admin = secrets.token_hex(32), secrets.token_hex(32)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    results = []
    timings = []
    bindings = {}
    def run(argv):
        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    run(['docker','volume','create','--label','chio.task=session-credentials',volume])
    run(['docker','volume','create','--label','chio.task=session-credentials',audit_volume])
    docker = ['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL',
              '--security-opt','no-new-privileges','--mount',f'type=volume,src={volume},dst=/workspace',
              '--mount',f'type=volume,src={audit_volume},dst=/audit',
              '--tmpfs','/tmp:rw,noexec,nosuid,size=16m',args.image]
    run(['docker','run','--rm','--network','none','--user','0','--mount',f'type=volume,src={volume},dst=/workspace',
         '--mount',f'type=volume,src={audit_volume},dst=/audit',
         '--entrypoint','node',args.image,'-e',"const f=require('fs');f.chownSync('/workspace',1000,1000);f.chownSync('/audit',1000,1000);f.writeFileSync('/workspace/forbidden.txt','original');f.chownSync('/workspace/forbidden.txt',1000,1000)"])
    policy = runtime / 'policy.yaml'
    policy.write_text('''kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 0
  durable_admission_mode: all
guards:
  forbidden_path:
    enabled: true
    additional_patterns: ["**/forbidden.txt"]
capabilities:
  default:
    tools:
      - server: "fs"
        tool: "*"
        operations: [invoke]
        ttl: 3600
        max_invocations: 8
''')
    command = [binary,'--session-db',str(runtime/'sessions.sqlite'),'--receipt-db',str(runtime/'receipts.sqlite'),
               '--authority-db',str(runtime/'authority.sqlite'),
               'mcp','serve-http','--policy',str(policy),'--server-id','fs','--shared-hosted-owner',
               '--listen',f'127.0.0.1:{port}','--',sys.executable,str(Path(__file__).resolve()),'--relay',*docker]
    private = runtime/'operator.json'
    private.write_text(json.dumps({'operatorToken':operator,'adminToken':admin,'command':command,'volume':volume},indent=2))
    private.chmod(0o600)
    def request(token, path, data=None, session=None, method='POST', timeout=15):
        started = time.monotonic()
        headers = {'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream','Content-Type':'application/json'}
        if session: headers.update({'MCP-Session-Id':session,'MCP-Protocol-Version':'2025-11-25'})
        req = urllib.request.Request(base+path, data=None if data is None else json.dumps(data).encode(), headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                raw=response.read().decode(); status=response.status; session_id=response.headers.get('MCP-Session-Id')
        except urllib.error.HTTPError as error:
            raw=error.read().decode(); status=error.code; session_id=None
        try:
            value=json.loads(raw)
        except ValueError:
            events=[]
            for line in raw.splitlines():
                if line.startswith('data: ') and line[6:].strip(): events.append(json.loads(line[6:]))
            value=events[-1] if events else raw
        timings.append({'httpMethod':method,'path':path,'rpcMethod':data.get('method') if isinstance(data,dict) else None,
                        'status':status,'elapsedMs':round((time.monotonic()-started)*1000,3)})
        return status,value,session_id
    def rpc(token, session, method, params=None, rid=1, timeout=15):
        return request(token,'/mcp',{'jsonrpc':'2.0','id':rid,'method':method,'params':params or {}},session,timeout=timeout)
    child = None
    log = open(runtime/'kernel.log','ab')
    def start():
        nonlocal child
        child=subprocess.Popen(command,env={**os.environ,'CHIO_AUTH_TOKEN':operator,'CHIO_ADMIN_TOKEN':admin},stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        (runtime/'kernel.pid').write_text(str(child.pid))
        for _ in range(100):
            if child.poll() is not None: raise RuntimeError('kernel startup failed; inspect retained log')
            try:
                status,_,_=request(admin,'/admin/health',method='GET',timeout=1)
                if status==200: return
            except (OSError,urllib.error.URLError): pass
            time.sleep(.1)
        raise RuntimeError('kernel readiness timed out')
    def stop():
        if child and child.poll() is None:
            child.terminate(); child.wait(timeout=20)
    def session(ttl=300, tools=None):
        status,body,sid=rpc(operator,None,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'credential-qualification','version':'1'}})
        assert status==200 and sid, (status,body)
        request(operator,'/mcp',{'jsonrpc':'2.0','method':'notifications/initialized'},sid)
        status,grant,_=request(admin,f'/admin/sessions/{sid}/credential',{'ttlSeconds':ttl,'allowedTools':tools or ['write_file','read_text_file','list_directory']})
        assert status==200,(status,grant)
        public={k:v for k,v in grant.items() if k!='bearerToken'}
        bindings[sid]=public
        return sid,grant['bearerToken'],public
    def verify_and_ack(token,sid,params,response):
        delivery=response['result']['_meta']['chioDelivery']
        envelope=response['result']['_meta']['chioEvidence']
        receipt=envelope['receipt']
        signer=(runtime/'sessions.sqlite.admission.kernel.pub').read_text().strip()
        assert receipt['kernel_key']==signer
        assert 'bbs_signature' not in receipt and receipt.get('algorithm') in [None,'ed25519']
        body={k:v for k,v in receipt.items() if k not in ['id','signature','algorithm','bbs_signature']}
        assert digest(body)==receipt['id']
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(bytes.fromhex(receipt['signature']),canonical_test_json({'id':receipt['id'],'body':body}))
        assert receipt['capability_id'] in bindings[sid]['capabilityIds']
        assert receipt['metadata']['attribution']['subject_key']==bindings[sid]['subjectKey']
        assert receipt['tool_server']=='fs' and receipt['tool_name']==params['name']
        assert receipt['action']['parameter_hash']==digest(params['arguments'])
        assert receipt['metadata']['receipt_context']['request_id']==params['_meta']['chioRequestId']
        admission=receipt['metadata']['admission_operation']
        assert admission['request_id']==params['_meta']['chioRequestId'] and admission['projected_state']=='completed' and admission['projected_dispatch_state']=='terminal'
        assert receipt['decision']['verdict']=='allow' and receipt['content_hash']==digest(envelope['output'])
        assert delivery['schema']=='chio.mcp.delivery-ack.v1'
        assert delivery['requestId']==params['_meta']['chioRequestId'] and delivery['requestHash']==digest({'method':'tools/call','params':params})
        assert delivery['receiptId']==receipt['id'] and delivery['resultHash']==receipt['content_hash']
        # Acknowledgement follows verified, fsynced caller storage, never just server send.
        local=runtime/'verified-outcomes';local.mkdir(mode=0o700,exist_ok=True)
        target=local/(hashlib.sha256((sid+delivery['requestId']).encode()).hexdigest()+'.json')
        with target.open('w') as stream:
            os.chmod(target,0o600);json.dump(response,stream);stream.flush();os.fsync(stream.fileno())
        directory=os.open(local,os.O_RDONLY);os.fsync(directory);os.close(directory)
        status,ack,_=rpc(token,sid,'chio/acknowledge',delivery)
        assert status==200 and ack['result']['acknowledged'] and ack['result']['requestId']==delivery['requestId']
    def call(token,sid,path,content,request_id):
        params={'name':'write_file','arguments':{'path':'/workspace/'+path,'content':content},'_meta':{'chioRequestId':request_id}}
        outcome=rpc(token,sid,'tools/call',params)
        if outcome[0]==200 and not outcome[1]['result'].get('isError'):
            verify_and_ack(token,sid,params,outcome[1])
        return outcome
    def observe():
        return json.loads(run(['docker','run','--rm','--network','none','--read-only','--mount',f'type=volume,src={volume},dst=/workspace,readonly',
            '--entrypoint','node',args.image,'-e',"const f=require('fs');console.log(JSON.stringify(Object.fromEntries(f.readdirSync('/workspace').map(n=>[n,f.readFileSync('/workspace/'+n,'utf8')]))))"]))
    def check(name,condition,details):
        record={'case':name,'passed':bool(condition),'details':details,'resource':observe()}
        results.append(record)
        (evidence/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        if not condition: raise AssertionError(name)
    try:
        start()
        for content in ['observer-control', 'original']:
            run(['docker','run','--rm','--network','none','--read-only','--mount',f'type=volume,src={volume},dst=/workspace',
                 '--entrypoint','node',args.image,'-e',"require('fs').writeFileSync('/workspace/forbidden.txt',process.argv[1])",content])
            check('forbidden_observer_control_'+content,observe()['forbidden.txt']==content,{'directResourceOwnerWrite':content})
        sid,token,binding=session()
        status,context,_=rpc(token,sid,'chio/execution-context')
        check('delegated_context',status==200 and context['result']['sessionCredential']==binding
              and context['result']['deliveryAcknowledgementVersion']=='1',context)
        status,catalog,_=rpc(token,sid,'tools/list')
        check('inventory_filtered',status==200 and sorted(t['name'] for t in catalog['result']['tools'])==binding['allowedTools'],catalog)
        before=observe()
        first=call(token,sid,'useful.txt','legitimate useful work','useful-1')
        check('useful_effect',first[0]==200 and observe().get('useful.txt')=='legitimate useful work',first[1])
        replay=call(token,sid,'useful.txt','legitimate useful work','useful-1')
        check('exact_owner_replay',replay[0]==200 and replay[1]==first[1],replay[1])
        hidden=rpc(token,sid,'tools/call',{'name':'move_file','arguments':{'source':'/workspace/useful.txt','destination':'/workspace/moved.txt'},'_meta':{'chioRequestId':'hidden-move'}})
        check('hidden_tool_denied',hidden[0]==403 and 'moved.txt' not in observe(),hidden[:2])
        init=rpc(token,None,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'bypass','version':'1'}})
        check('new_issuance_denied',init[0]==401,init[:2])
        sid2,token2,_=session()
        wrong=call(token,sid2,'wrong-session.txt','forbidden','wrong-session')
        check('wrong_session_denied',wrong[0]==401 and 'wrong-session.txt' not in observe(),wrong[:2])
        for path in ['/admin/health',f'/admin/sessions/{sid}/credential',f'/admin/sessions/{sid}/credential/revoke']:
            denied=request(token,path,{'ttlSeconds':300,'allowedTools':['write_file']},method='GET' if path.endswith('health') else 'POST')
            check('admin_denied_'+path.rsplit('/',1)[-1],denied[0]==401,denied[:2])
        check('observer_negative_control',before=={'forbidden.txt':'original'} and observe().get('useful.txt')=='legitimate useful work',{'before':before})
        expired_sid,expired_token,_=session(ttl=1)
        time.sleep(1.1)
        expired=call(expired_token,expired_sid,'expired.txt','forbidden','expired')
        check('expiry_denied',expired[0]==401 and 'expired.txt' not in observe(),expired[:2])
        revoked_sid,revoked_token,_=session()
        request(admin,f'/admin/sessions/{revoked_sid}/credential/revoke',{})
        revoked=call(revoked_token,revoked_sid,'revoked.txt','forbidden','revoked')
        check('credential_revocation_denied',revoked[0]==401 and 'revoked.txt' not in observe(),revoked[:2])
        cap_sid,cap_token,cap_binding=session()
        request(admin,'/admin/revocations',{'capability_id':cap_binding['capabilityIds'][0]})
        revoked_cap=call(cap_token,cap_sid,'revoked-cap.txt','forbidden','revoked-cap')
        check('capability_revocation_denied',revoked_cap[0]==200 and revoked_cap[1]['result']['isError'] and 'revoked-cap.txt' not in observe(),revoked_cap[:2])
        forbidden=call(token2,sid2,'forbidden.txt','forbidden replacement','forbidden')
        check('kernel_denial_no_effect',forbidden[0]==200 and forbidden[1]['result']['isError'] and observe()['forbidden.txt']=='original',forbidden[:2])
        fenced=call(token2,sid2,'after-denial.txt','not permitted','after-denial')
        check('denial_fences_new_ids',fenced[0]==409 and 'after-denial.txt' not in observe(),fenced[:2])
        budget_sid,budget_token,budget_binding=session()
        budget_calls=[call(budget_token,budget_sid,f'budget-{index}.txt','permitted',f'budget-{index}') for index in range(8)]
        exhausted=call(budget_token,budget_sid,'budget-overflow.txt','forbidden','budget-overflow')
        check('aggregate_budget_preserved',all(result[0]==200 and not result[1]['result'].get('isError') for result in budget_calls)
              and exhausted[0]==200 and exhausted[1]['result']['isError'] and 'budget-overflow.txt' not in observe(),exhausted[:2])
        unknown_sid,unknown_token,unknown_binding=session()
        timed_out=False
        try:
            rpc(unknown_token,unknown_sid,'tools/call',{'name':'write_file','arguments':{'path':'/workspace/unknown.txt','content':'external effect exists'},'_meta':{'chioRequestId':'unknown'}},timeout=.5)
        except (TimeoutError,OSError,urllib.error.URLError): timed_out=True
        time.sleep(4.5)
        fenced=call(unknown_token,unknown_sid,'after-unknown.txt','must not dispatch','after-unknown')
        check('lost_response_owner_fence',timed_out and observe().get('unknown.txt')=='external effect exists' and fenced[0]==409 and 'after-unknown.txt' not in observe(),fenced[:2])
        rotation_status,rotation,_=request(admin,f'/admin/sessions/{unknown_sid}/credential',
            {'ttlSeconds':300,'allowedTools':unknown_binding['allowedTools']})
        assert rotation_status==200
        unknown_token=rotation.pop('bearerToken')
        rotated=call(unknown_token,unknown_sid,'after-rotation.txt','must not dispatch','after-rotation')
        check('credential_rotation_preserves_fence',rotation['capabilityIds']==unknown_binding['capabilityIds']
              and rotated[0]==409 and 'after-rotation.txt' not in observe(),rotated[:2])
        stop(); start()
        resumed=call(token,sid,'resumed.txt','same retained identity','resumed')
        check('retained_session_restart',resumed[0]==200 and observe().get('resumed.txt')=='same retained identity',resumed[:2])
        uncertain=call(unknown_token,unknown_sid,'after-restart.txt','must not dispatch','after-restart')
        check('unknown_fence_survives_restart',uncertain[0]==409 and 'after-restart.txt' not in observe(),uncertain[:2])
        proxy_sid,proxy_token,proxy_binding=session()
        upstream_base=base
        proxy_consumed=threading.Event()
        class DropAfterResponse(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                payload=self.rfile.read(int(self.headers['Content-Length']))
                forwarded={k:v for k,v in self.headers.items() if k.lower() not in ['host','connection']}
                req=urllib.request.Request(upstream_base+self.path,data=payload,headers=forwarded,method='POST')
                with urllib.request.urlopen(req,timeout=20) as response:
                    response.read()  # Consume the complete original response, including acknowledgement challenge.
                proxy_consumed.set()
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
        proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),DropAfterResponse)
        proxy.daemon_threads=True
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        lost_params={'name':'write_file','arguments':{'path':'/workspace/proxy-lost.txt','content':'one committed external effect'},'_meta':{'chioRequestId':'proxy-original'}}
        guest_journal=runtime/'guest-uncertainty.json'
        guest_journal.write_text(json.dumps({'state':'pending','requestId':'proxy-original'}))
        disconnected=False
        try:
            base=f'http://127.0.0.1:{proxy.server_port}'
            rpc(proxy_token,proxy_sid,'tools/call',lost_params)
        except (OSError,urllib.error.URLError,http.client.RemoteDisconnected): disconnected=True
        finally:
            base=upstream_base;proxy.shutdown();proxy.server_close()
        assert disconnected and proxy_consumed.wait(2)
        guest_journal.unlink()  # Deliberately erase only this test agent's local pending record.
        blocked=call(proxy_token,proxy_sid,'proxy-new-id.txt','must not redispatch','proxy-new-id')
        check('proxy_lost_completed_response_owner_fence',blocked[0]==409 and observe().get('proxy-lost.txt')=='one committed external effect'
              and 'proxy-new-id.txt' not in observe(),{'blocked':blocked[:2],'upstreamResponseFullyConsumed':True,'guestJournalDeleted':True})
        rotated_status,rotated_binding,_=request(admin,f'/admin/sessions/{proxy_sid}/credential',{'ttlSeconds':300,'allowedTools':proxy_binding['allowedTools']})
        assert rotated_status==200
        proxy_token=rotated_binding.pop('bearerToken');bindings[proxy_sid]=rotated_binding
        blocked=call(proxy_token,proxy_sid,'proxy-rotated.txt','must not redispatch','proxy-rotated')
        check('unacknowledged_rotation_fence',blocked[0]==409 and rotated_binding['capabilityIds']==proxy_binding['capabilityIds'] and 'proxy-rotated.txt' not in observe(),blocked[:2])
        stop();start()
        blocked=call(proxy_token,proxy_sid,'proxy-restart.txt','must not redispatch','proxy-restart')
        check('unacknowledged_restart_fence',blocked[0]==409 and 'proxy-restart.txt' not in observe(),blocked[:2])
        replay_status,original,_=rpc(proxy_token,proxy_sid,'tools/call',lost_params,rid=100)
        check('exact_original_response_recovery',replay_status==200 and original['id']==100 and original['result']['_meta']['chioDelivery']['requestId']=='proxy-original',original)
        for field in ['requestId','requestHash','receiptId','resultHash','acknowledgement']:
            forged=copy.deepcopy(original['result']['_meta']['chioDelivery']);forged[field]='wrong'
            rejected=rpc(proxy_token,proxy_sid,'chio/acknowledge',forged)
            check('ack_rejects_'+field,rejected[0] in [403,409],rejected[:2])
        verify_and_ack(proxy_token,proxy_sid,lost_params,original)
        continued=call(proxy_token,proxy_sid,'proxy-continued.txt','useful continuation after verified recovery','proxy-continued')
        check('verified_durable_replay_ack_allows_continuation',continued[0]==200 and observe().get('proxy-continued.txt')=='useful continuation after verified recovery',continued[:2])
        stop()
        (runtime/'sessions.sqlite').rename(runtime/'sessions-preserved.sqlite')
        start()
        lost=call(token,sid,'lost-session.txt','must not dispatch','lost-session')
        check('missing_session_no_fresh_issuance',lost[0] in [401,404] and 'lost-session.txt' not in observe(),lost[:2])
    finally:
        stop(); log.close()
        (evidence/'timings.json').write_text(json.dumps(timings,indent=2)+'\n')
        (evidence/'kernel.log').write_bytes((runtime/'kernel.log').read_bytes())
        (evidence/'identity.json').write_text(json.dumps({'kernelSha256':identity,'source':run(['git','rev-parse','HEAD']).strip(),
            'sourceDirty':run(['git','status','--short']),'image':args.image,'volume':volume,'auditVolume':audit_volume,'runtime':str(runtime),
            'port':port,'cryptographyVersion':cryptography.__version__,'cases':len(results),'passed':sum(r['passed'] for r in results)},indent=2)+'\n')
    print(json.dumps({'passed':len(results),'evidence':str(evidence),'runtime':str(runtime),'volume':volume}))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--relay': sys.exit(relay(sys.argv[2:]))
    main()
