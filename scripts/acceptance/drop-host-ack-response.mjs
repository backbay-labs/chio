// Test-only: the owner accepted the delivery proof, but its confirmation never
// reaches the guest. The original signed result has already reached that guest.
import {ServerResponse} from "node:http";
import {appendFileSync,closeSync,openSync} from "node:fs";
import {createHash} from "node:crypto";
const path=process.env.CHIO_HOST_ACK_FAULT_LOG;
if(!path?.startsWith("/"))throw new Error("Fresh absolute CHIO_HOST_ACK_FAULT_LOG required");
closeSync(openSync(path,"wx",0o600));
const end=ServerResponse.prototype.end;
ServerResponse.prototype.end=function(chunk,...args){
 let value;
 try{value=JSON.parse(String(chunk));}catch{}
 if(value?.jsonrpc==="2.0"&&value.result?.schema==="chio.mcp.delivery-ack.v1"&&value.result.acknowledged===true){
  appendFileSync(path,JSON.stringify({cutpoint:"owner-acknowledged-before-guest-confirmation",requestId:value.result.requestId,receiptId:value.result.receiptId,frameSha256:createHash("sha256").update(chunk).digest("hex")})+"\n");
  this.destroy();return this;
 }
 return end.call(this,chunk,...args);
};
