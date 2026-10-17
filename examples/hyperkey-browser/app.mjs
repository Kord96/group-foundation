import {HyperKeyHost,base64url,fromBase64url,verifyEd25519,HYPERKEY_GROUP_PROFILE} from "@group-foundation/hyperkey";
import {prepareNativeHyperKeyFounder} from "@group-foundation/hyperkey/native";
import initialize,* as native from "@group-foundation/group-core/native";
import {browserPersistence} from "./persistence.mjs";
const status=document.querySelector("#status"),button=document.querySelector("#create"),list=document.querySelector("#keys");
const message=new TextEncoder().encode("hyperkey.browser-qualification.v1");
try{
  await initialize();
  const ports=await browserPersistence("hyperkey-browser-qualification-v1"),prepared=new Map();
  const host=new HyperKeyHost({...ports,group:{async stageFounder(input,signal){
    const group=prepared.get(input.founder.copyId);
    if(!group)throw new Error("Founder has not been authorized");
    return group.stageFounder(input,signal);
  }}});
  const qualification={
    async create(){
      const delivery=await crypto.subtle.generateKey({name:"X25519"},true,["deriveBits"]);
      const evidence=new TextEncoder().encode("explicit browser qualification founder");
      const founder=await prepareNativeHyperKeyFounder({native,evidence,copyId:base64url(crypto.getRandomValues(new Uint8Array(32))),recipientDeliveryKey:new Uint8Array(await crypto.subtle.exportKey("raw",delivery.publicKey)),authority:{async authorizeFounder(input){
        if(input.profile!==HYPERKEY_GROUP_PROFILE||new TextDecoder().decode(input.evidence)!==new TextDecoder().decode(evidence))throw new Error("Qualification evidence differs");
        return {identityRevision:1n,identityValidUntilMs:BigInt(input.nowMs+60000),governanceRevision:1n,governanceValidUntilMs:BigInt(input.nowMs+60000)};
      }}});
      prepared.set(founder.founder.copyId,founder.group);
      const key=await host.create({founder:founder.founder});
      await render();return {id:key.id,copyId:key.copyId,descriptor:key.descriptor};
    },
    async list(){return (await host.list()).map(({id,copyId,descriptor,status})=>({id,copyId,descriptor,status}));},
    async sign(id,copyId){
      const key=await host.open(id,copyId);if(!key)throw new Error("Unknown Copy");
      const signature=await key.sign(message);
      if(!await verifyEd25519(fromBase64url(key.descriptor.publicKey,32),message,signature))throw new Error("Signature verification failed");
      return base64url(signature);
    },
    async forget(id,copyId){await host.forgetCopy(id,copyId);await render();},
  };
  window.qualification=qualification;
  async function render(){
    list.replaceChildren();
    for(const key of await qualification.list()){
      const row=document.createElement("li"),label=document.createElement("strong"),descriptor=document.createElement("pre");
      label.textContent=`${key.id} · ${key.status}`;descriptor.textContent=JSON.stringify(key.descriptor,null,2);row.append(label,descriptor);
      for(const [label,action] of [["Sign challenge",async()=>{document.querySelector("#signature").textContent=await qualification.sign(key.id,key.copyId);}],["Forget this Copy",()=>qualification.forget(key.id,key.copyId)]]){
        const button=document.createElement("button");button.textContent=label;button.disabled=key.status!=="ready";button.onclick=()=>run(action);row.append(button);
      }
      list.append(row);
    }
    status.textContent="Sealed Copies loaded.";
  }
  async function run(action){try{await action();}catch(error){status.textContent=error.message;}}
  button.onclick=()=>run(()=>qualification.create());button.disabled=false;
  await render();
}catch(error){status.textContent=error.message;throw error;}
