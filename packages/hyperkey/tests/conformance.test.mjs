import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";
import * as hk from "../dist/index.js";
const vector=JSON.parse(await readFile(new URL("../spec/v1-vectors.json",import.meta.url),"utf8"));
test("frozen v1 descriptor, signing and Copy transcript vectors conform exactly",async()=>{
  const seed=hk.fromBase64url(vector.seed,32),publicKey=await hk.publicKeyForEd25519Seed(seed);
  const {descriptor,id}=await hk.createHyperKeyDescriptor(vector.descriptor.groupId,publicKey);
  assert.deepEqual(descriptor,vector.descriptor);assert.equal(id,vector.descriptorId);
  assert.equal(hk.base64url(hk.descriptorCanonicalBytes(descriptor)),vector.canonicalDescriptor);
  assert.equal(hk.base64url(hk.hyperKeyApplicationTranscript(vector.binding)),vector.applicationTranscript);
  assert.equal(hk.base64url(hk.hyperKeyAdmissionBinding(descriptor.groupId,vector.copy)),vector.admissionBinding);
  const signature=await hk.signEd25519(seed,hk.fromBase64url(vector.challenge));
  assert.equal(hk.base64url(signature),vector.signature);
  assert.equal(await hk.verifyEd25519(publicKey,hk.fromBase64url(vector.challenge),signature),true);
  assert.equal(Object.isFrozen(descriptor),true);
  assert.throws(()=>hk.assertHyperKeyDescriptor({...descriptor,schema:"zagel.hyperkey.descriptor.v1"}));
});
