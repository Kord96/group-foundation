/** Self-contained consumer adapter; every cooperating writer uses the same lock. */
export async function browserPersistence(name) {
  const request = indexedDB.open(name,1);
  request.onupgradeneeded=()=>{request.result.createObjectStore("records");request.result.createObjectStore("sealing-keys");};
  const db=await result(request);
  const lock=`hyperkey-browser:${name}`;
  const read=async keys=>{
    const transaction=db.transaction("records","readonly"),store=transaction.objectStore("records");
    const values=await Promise.all(keys.map(key=>result(store.get(key))));
    return new Map(keys.flatMap((key,index)=>values[index]===undefined?[]:[[key,new Uint8Array(values[index])]]));
  };
  const persistence={
    read:keys=>navigator.locks.request(lock,()=>read(keys)),
    transact:(keys,operation)=>navigator.locks.request(lock,async()=>{
      const records=await read(keys),value=await operation(records);
      const transaction=db.transaction("records","readwrite",{durability:"strict"}),store=transaction.objectStore("records");
      const committed=completion(transaction);
      for(const key of keys){if(records.has(key))store.put(records.get(key),key);else store.delete(key);}
      await committed;
      return value;
    }),
  };
  const key=purpose=>navigator.locks.request(`${lock}:sealing:${purpose}`,async()=>{
    const readTx=db.transaction("sealing-keys","readonly");
    const existing=await result(readTx.objectStore("sealing-keys").get(purpose));
    if(existing)return existing;
    const created=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
    const transaction=db.transaction("sealing-keys","readwrite",{durability:"strict"}),committed=completion(transaction);
    transaction.objectStore("sealing-keys").put(created,purpose);
    await committed;
    return created;
  });
  const sealing={
    async seal(purpose,plaintext,associatedData){
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:associatedData},await key(purpose),plaintext));
      return new Uint8Array([...iv,...encrypted]);
    },
    async open(purpose,sealed,associatedData){
      return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:sealed.slice(0,12),additionalData:associatedData},await key(purpose),sealed.slice(12)));
    },
  };
  return {persistence,sealing,commitOutcome:{isUncertain:()=>false},close:()=>db.close()};
}
function result(request){return new Promise((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);});}
function completion(transaction){return new Promise((resolve,reject)=>{transaction.oncomplete=()=>resolve();transaction.onabort=()=>reject(transaction.error??new Error("IndexedDB transaction aborted"));transaction.onerror=()=>{};});}
