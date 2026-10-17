import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const server=createServer(async(req,res)=>{
  try {
    if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Group product binding</title>');return;}
    const filename=({'/foundation_group.js':'foundation_group.js','/foundation_group_bg.wasm':'foundation_group_bg.wasm'})[req.url];
    if(!filename){res.writeHead(404).end();return;}
    res.setHeader('Content-Type',filename.endsWith('.wasm')?'application/wasm':'text/javascript');
    res.end(await readFile(new URL(`../generated/${filename}`,import.meta.url)));
  }catch{res.writeHead(500).end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
let browser;
try {
  browser=await chromium.launch({headless:true,...(process.env.GROUP_FOUNDATION_CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.GROUP_FOUNDATION_CHROMIUM_EXECUTABLE_PATH}:{})});
  const page=await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  const result=await page.evaluate(async()=>{
    const native=await import('/foundation_group.js');await native.default();
    const b=value=>new TextEncoder().encode(value),u=(...v)=>new Uint8Array(v);
    const limits={maxPastEpochs:4,outOfOrderTolerance:4,maxForwardDistance:32};
    const profile={...limits,capabilities:u(2,0,1,2,0,1,2,0,6,4,0,8,0,10,2,0,1),contextExtensions:u(4,0,6,1,0),leafExtensions:u(0)};
    const credential=value=>{const v=b(value);return u(0,1,v.length,...v);};
    const request=extra=>({additions:[],removals:[],componentUpdates:[],...extra});
    const restore=stage=>native.NativeProductClient.fromCustody(stage.custody);
    const same=(a,c)=>a.length===c.length&&a.every((v,i)=>v===c[i]);
    const groupId=b('browser-product-group');
    const fresh=new native.NativeProductClient();
    const founder=restore(fresh.stageCreate(groupId,credential('browser founder'),profile));
    const before=founder.exportCustody();
    const recipientFresh=new native.NativeProductClient();
    const kp=recipientFresh.stageKeyPackage(credential('browser recipient'),profile);
    const recipient=restore(kp);
    const add=founder.stageCommit(groupId,request({additions:[kp.keyPackage]}),b('browser aad'));
    const ownAddRetained=founder.stageProcess(groupId,add.commit,'ownCommit').selfRemoved===false;
    const joined=recipient.stageJoin(add.welcome,limits);
    const sender=restore(add),receiver=restore(joined);
    const sealed=sender.stageSeal(groupId,b('real browser application'),b('browser application aad'));
    const opened=receiver.stageProcess(groupId,sealed.frame,'application');
    let rejected=false;try{receiver.stageProcess(groupId,add.commit,'application');}catch{rejected=true;}
    const key=b('group-foundation.sidecar.browser.sidecar');
    const sidecar=restore({custody:sender.stageRecords([{key,value:b('opaque sidecar')}])});
    const inline=sender.stageCommit(groupId,request({componentUpdates:[{id:42,value:b('browser opaque update')}]}),u());
    const ownUpdateRetained=sender.stageProcess(groupId,inline.commit,'ownCommit').selfRemoved===false;
    const inlineFacts=receiver.stageProcess(groupId,inline.commit,'member').proposals;
    const removal=sender.stageCommit(groupId,request({removals:[receiver.inspect(groupId).ownLeaf],componentUpdates:[{id:42,value:b('browser terminal state')}]}),u());
    const ownRemovalRetained=sender.stageProcess(groupId,removal.commit,'ownCommit').selfRemoved===false;
    const removedLeafBound=receiver.stageProcess(groupId,removal.commit,'ownCommit').selfRemoved===true;
    const leave=receiver.stageSelfRemove(groupId,u());
    const queued=sender.stageProcess(groupId,leave.frame,'member');
    const queuedSender=restore(queued);
    const selected=queuedSender.stageCommit(groupId,request({proposalReferences:[queued.proposals[0].reference]}),u());
    const ownReferenceRetained=queuedSender.stageProcess(groupId,selected.commit,'ownCommit').selfRemoved===false;
    const queuedReceiver=restore(receiver.stageProcess(groupId,leave.frame,'member'));
    const selfRemoveLeafBound=queuedReceiver.stageProcess(groupId,selected.commit,'ownCommit').selfRemoved===true;
    const referenced=queuedReceiver.stageProcess(groupId,selected.commit,'member');
    const inactive=restore(referenced);
    const inactivePresent=inactive.hasGroup(groupId)&&!inactive.inspect(groupId).active;
    const inactiveDeleted=!restore({custody:inactive.stageDelete(groupId)}).hasGroup(groupId);
    const otherId=b('browser unrelated group'),foreignKey=b('group-foundation.sidecar.browser.unrelated');
    const anchor=restore(sidecar.stageCreate(otherId,credential('browser unrelated'),profile));
    const live=restore({custody:anchor.stageRecords([{key:foreignKey,value:b('unrelated live record')}])});
    const liveBefore=live.exportCustody(),anchorBefore=anchor.exportCustody();
    const deleted=restore({custody:anchor.stageDelete(groupId)});
    const terminal=deleted.stageRecords([{key,value:null}]);
    const installed=restore({custody:live.stageCheckpoint(anchorBefore,terminal,groupId,[key])});
    const expected=restore({custody:restore({custody:live.stageDelete(groupId)}).stageRecords([{key,value:null}])});
    let foreignRejected=false,unknownRejected=false,boundsRejected=false;
    try{live.stageCheckpoint(anchorBefore,deleted.stageDelete(otherId),groupId,[key]);}catch{foreignRejected=true;}
    try{live.stageCheckpoint(anchorBefore,anchorBefore,b('unknown terminal group'),[]);}catch{unknownRejected=true;}
    try{live.hasGroup(new Uint8Array(256));}catch{boundsRejected=true;}
    const proof=sender.signProof(b('browser product proof domain'));
    const publicKey=await crypto.subtle.importKey('raw',proof.signingKey,{name:'Ed25519'},false,['verify']);
    const signatureValid=await crypto.subtle.verify('Ed25519',publicKey,proof.signature,b('browser product proof domain'));
    return {epoch:opened.projection.epoch,members:opened.projection.members.length,
      plaintext:new TextDecoder().decode(opened.plaintext),aad:new TextDecoder().decode(opened.aad),
      detached:same(before,founder.exportCustody()),contexts:same(add.projection.context,joined.projection.context),
      sidecar:new TextDecoder().decode(sidecar.readRecord(key)),signatureValid,rejected,
      ownAddRetained,ownUpdateRetained,ownRemovalRetained,removedLeafBound,ownReferenceRetained,selfRemoveLeafBound,
      inlineOrigin:inlineFacts.length>0&&inlineFacts.every(item=>item.origin==='inline'&&item.reference===undefined),
      referenceOrigin:referenced.proposals[0].origin==='reference'&&same(referenced.proposals[0].reference,queued.proposals[0].reference),
      inactivePresent,inactiveDeleted,
      terminalDetached:same(liveBefore,live.exportCustody())&&same(anchorBefore,anchor.exportCustody()),
      terminalGroups:!installed.hasGroup(groupId)&&installed.hasGroup(otherId),
      terminalRecords:installed.readRecord(key)===undefined&&new TextDecoder().decode(installed.readRecord(foreignKey))==='unrelated live record',
      terminalExact:same(installed.exportCustody(),expected.exportCustody()),foreignRejected,unknownRejected,boundsRejected};
  });
  assert.deepEqual(result,{epoch:'1',members:2,plaintext:'real browser application',aad:'browser application aad',detached:true,contexts:true,sidecar:'opaque sidecar',signatureValid:true,rejected:true,
    ownAddRetained:true,ownUpdateRetained:true,ownRemovalRetained:true,removedLeafBound:true,ownReferenceRetained:true,selfRemoveLeafBound:true,
    inlineOrigin:true,referenceOrigin:true,inactivePresent:true,inactiveDeleted:true,terminalDetached:true,terminalGroups:true,terminalRecords:true,terminalExact:true,foreignRejected:true,unknownRejected:true,boundsRejected:true});
  console.log('Group product web binding: Chromium MLS, authenticated proposal origins, terminal deletion/checkpoint, foreign rejection and detached custody checks passed');
}finally {
  await browser?.close();await new Promise(resolve=>server.close(resolve));
}
