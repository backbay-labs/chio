#!/usr/bin/env python3
"""Real short-capability expiry on one explicitly isolated resource owner."""
import argparse, hashlib, json, os, sqlite3, subprocess, time, urllib.error, urllib.request, uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = Path('/tmp/chio-capability-expiry-20260909')
STATE = Path('/Users/connor/.local/share/chio-required-operators/capability-expiry-20260909')
BRIDGE = Path('/Users/connor/.local/share/chio-required-candidates/20260909/install/operator-bridge/node_modules/@chio/bridge')
PROTOCOL = '2025-11-25'


def write(path, data, private=False):
    with path.open('x') as stream:
        if private: os.chmod(path, 0o600)
        json.dump(data, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def rpc(endpoint, token, session, method, params, events, label):
    body={'jsonrpc':'2.0','id':str(uuid.uuid4()),'method':method,'params':params}
    req=urllib.request.Request(endpoint+'/mcp',data=json.dumps(body).encode(),headers={
        'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json, text/event-stream',
        'MCP-Protocol-Version':PROTOCOL,'MCP-Session-Id':session})
    before=time.time()
    try: response=urllib.request.urlopen(req,timeout=20)
    except urllib.error.HTTPError as error: response=error
    with response:
        if 'text/event-stream' in response.headers.get('Content-Type',''):
            result=None
            for raw in response:
                line=raw.decode().strip()
                if line.startswith('data:'):
                    value=json.loads(line[5:].strip())
                    if value.get('id')==body['id']: result=value;break
        else:
            raw=response.read().decode()
            try:result=json.loads(raw)
            except ValueError:result={'text':raw}
        status=response.status
    events.append({'label':label,'startedAtEpoch':before,'completedAtEpoch':time.time(),'request':body,'status':status,'response':result})
    return status,result


def observe(operator):
    js="const f=require('fs');let r={};for(const n of ['before-expiry.txt','after-expiry.txt','delegated-after-expiry.txt']){const p='/workspace/'+n;r[n]=f.existsSync(p)?{exists:true,content:f.readFileSync(p,'utf8')}:{exists:false}}process.stdout.write(JSON.stringify(r));"
    command=['docker','run','--rm','--network','none','--read-only','--mount',f"type=volume,src={operator['volume']},dst=/workspace,readonly",'--entrypoint','node',operator['image'],'-e',js]
    return json.loads(subprocess.run(command,check=True,capture_output=True,text=True).stdout)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--prepare-only',action='store_true');parser.add_argument('--name',default='probe');args=parser.parse_args()
    if not args.name.replace('-','').isalnum():parser.error('use an alphanumeric name')
    public=BASE/args.name;public.mkdir(mode=0o700)
    private=STATE/('qualification-'+args.name);private.mkdir(mode=0o700)
    operator=json.loads((STATE/'operator.json').read_text())
    request={'endpoint':f"http://127.0.0.1:{operator['port']}",'bearerToken':operator['agentToken'],'adminToken':operator['adminToken'],
        'credentialTtlSeconds':900,'trustedSigners':[(STATE/'sessions.sqlite.admission.kernel.pub').read_text().strip()],
        'serverId':'fs','sessionId':str(uuid.uuid4()),'journalDir':str(private/'journal'),
        'allowedTools':['read_text_file','write_file','edit_file','list_directory']}
    write(private/'prepare.json',request,True)
    started=time.time()
    prep=subprocess.run(['node',str(BRIDGE/'dist/prepare-gateway.js'),str(private/'prepare.json'),str(private/'gateway.json')],capture_output=True,text=True,timeout=30)
    (public/'prepare.log').write_text(prep.stdout+prep.stderr);prep.check_returncode()
    config=json.loads((private/'gateway.json').read_text());prepared=time.time()
    with sqlite3.connect(f'file:{STATE}/sessions.sqlite?mode=ro',uri=True) as conn:
        row=conn.execute('SELECT record_json FROM remote_active_sessions WHERE session_id=?',(config['execution']['sessionId'],)).fetchone()
    record=json.loads(row[0]);caps=record['issued_capabilities'];assert len(caps)==1
    cap=caps[0];assert cap['id']==config['execution']['capabilityId'];assert cap['subject']==config['execution']['subjectKey']
    key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(cap['issuer']));sig=bytes.fromhex(cap['signature'])
    bodies=[{k:v for k,v in cap.items() if k not in ['signature','algorithm']},{k:v for k,v in cap.items() if k not in ['signature','algorithm','schema']}]
    verified=[]
    for i,body in enumerate(bodies):
        try:key.verify(sig,json.dumps(body,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode());verified.append(i)
        except Exception:pass
    assert verified,'capability signature did not verify'
    credential=config['sessionCredential'];assert cap['expires_at']-cap['issued_at']==10
    assert credential['expiresAt']==cap['expires_at']
    assert prepared<cap['expires_at']
    report={'kernelSha256':operator['kernelSha256'],'kernelSource':'d8c5f53705173e614a853bad6c0a85acfdf1212b','image':operator['image'],
        'policySha256':operator['policySha256'],'capability':cap,'capabilitySignatureVerifiedAgainstEmbeddedIssuer':True,
        'signatureBody':'schema-aware' if verified==[0] else 'legacy plain body','sessionCredential':credential,
        'credentialRequestedTtlSeconds':900,'preparationStartedAtEpoch':started,'preparedAtEpoch':prepared,
        'secondsRemainingAtPreparation':cap['expires_at']-prepared,'gatewayConfig':str(private/'gateway.json'),
        'sourceContract':'session_credentials.rs clamps delegated expiresAt to min(issued capability expiries, requested credential TTL)',
        'claims':'No delegated credential can outlive its capability. Optional inner-kernel probe uses trusted operator admission bearer, not a real host.'}
    write(public/'binding.json',report)
    if args.prepare_only:
        print(json.dumps({'gatewayConfig':report['gatewayConfig'],'binding':str(public/'binding.json'),'expiresAt':cap['expires_at']}));return
    events=[];endpoint=request['endpoint'];session=config['execution']['sessionId']
    status,response=rpc(endpoint,config['execution']['bearerToken'],session,'chio/execution-context',{},events,'delegated-context-before-expiry');assert status==200
    status,response=rpc(endpoint,operator['agentToken'],session,'tools/call',{'name':'write_file','arguments':{'path':'/workspace/before-expiry.txt','content':'actual capability was live\n'},'_meta':{'chioRequestId':'short-cap-before'}},events,'operator-kernel-write-before-expiry')
    assert status==200 and not response['result'].get('isError'),response
    observed=observe(operator);assert observed['before-expiry.txt']['content']=='actual capability was live\n'
    events.append({'label':'independent-observer-before-expiry','atEpoch':time.time(),'observation':observed})
    while time.time()<=cap['expires_at']+1:time.sleep(min(0.25,max(0.001,cap['expires_at']+1-time.time())))
    status,response=rpc(endpoint,config['execution']['bearerToken'],session,'tools/call',{'name':'write_file','arguments':{'path':'/workspace/delegated-after-expiry.txt','content':'must not happen'},'_meta':{'chioRequestId':'short-cap-delegated-after'}},events,'delegated-write-after-capability-and-credential-expiry');assert status==401,(status,response)
    status,response=rpc(endpoint,operator['agentToken'],session,'tools/call',{'name':'write_file','arguments':{'path':'/workspace/after-expiry.txt','content':'must not happen'},'_meta':{'chioRequestId':'short-cap-inner-after'}},events,'operator-inner-kernel-write-after-capability-expiry');assert status==200 and response['result'].get('isError'),response
    assert 'expired' in json.dumps(response).lower(),response
    observed=observe(operator);assert not observed['after-expiry.txt']['exists'];assert not observed['delegated-after-expiry.txt']['exists']
    events.append({'label':'independent-observer-after-expiry','atEpoch':time.time(),'observation':observed})
    command=['docker','run','--rm','--network','none','--read-only','--mount',f"type=volume,src={operator['auditVolume']},dst=/audit,readonly",'--entrypoint','node',operator['image'],'-e',"process.stdout.write(require('fs').readFileSync('/audit/dispatch.jsonl'))"]
    audit=subprocess.run(command,check=True,capture_output=True,text=True).stdout;(public/'resource-dispatch.jsonl').write_text(audit)
    entries=[json.loads(line) for line in audit.splitlines()];assert [(e['tool'],e['path']) for e in entries]==[('write_file','/workspace/before-expiry.txt')]
    write(public/'raw.json',events);write(public/'result.json',{'passed':True,'completedAtEpoch':time.time(),'newResourceDispatches':1,'capabilityExpiredAtEpoch':cap['expires_at'],'hostAcceptanceClaim':False})
    print(json.dumps({'passed':True,'evidence':str(public),'expiresAt':cap['expires_at']}))

if __name__=='__main__':main()
