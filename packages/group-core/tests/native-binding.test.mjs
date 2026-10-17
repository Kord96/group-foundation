import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const generatedModule = new URL("../generated/foundation_group.js", import.meta.url);
const generatedWasm = new URL("../generated/foundation_group_bg.wasm", import.meta.url);
let native;

try {
  await access(generatedModule);
  await access(generatedWasm);
  native = await import(generatedModule.href);
  // The web target accepts bytes too, which lets this browser-oriented module
  // run in Node without relying on fetch(file:...).
  await native.default({ module_or_path: await readFile(generatedWasm) });
} catch (error) {
  throw new Error("@group-foundation/group-core native WebAssembly binding is required for qualification; run pnpm --filter @group-foundation/group-core build:wasm", { cause: error });
}

const enc = new TextEncoder();
const bytes = (value) => enc.encode(value);
const equalBytes = (actual, expected) => assert.deepEqual([...actual], [...expected]);

test("native web binding stages real detached MLS lifecycle and rejects substitutions", () => {
  const groupId = bytes("group-native-binding-00000001");
  const wrongGroupId = bytes("group-native-binding-00000002");
  const profile = bytes("product-neutral-profile/v1");
  const wrongProfile = bytes("product-neutral-profile/v2");
  const authority = new native.NativeAuthorityFacts(7n, 10_000n, 9n, 10_000n);

  let founder = new native.NativeClient(bytes("validated:founder"));
  const created = founder.createGroup(groupId, profile, authority, 100n);
  founder = native.NativeClient.fromSnapshot(created.snapshot);

  let recipient = new native.NativeClient(bytes("validated:recipient"));
  const recipientPackage = recipient.createKeyPackage(profile);
  recipient = native.NativeClient.fromSnapshot(recipientPackage.snapshot);
  assert.notDeepEqual([...founder.memberId()], [...recipient.memberId()]);

  assert.throws(() => founder.stageAdd(groupId, wrongProfile, recipientPackage.keyPackage, authority, 100n));
  const add = founder.stageAdd(groupId, profile, recipientPackage.keyPackage, authority, 100n);
  founder = native.NativeClient.fromSnapshot(add.snapshot);
  assert.equal(add.epoch, "1");

  assert.throws(() => recipient.stageJoin(wrongGroupId, profile, add.welcome, add.ratchetTree, authority, 100n));
  const joined = recipient.stageJoin(groupId, profile, add.welcome, add.ratchetTree, authority, 100n);
  recipient = native.NativeClient.fromSnapshot(joined.snapshot);

  const sealed = founder.stageSealApplication(groupId, profile, bytes("opaque application frame"), authority, 101n);
  assert.throws(() => recipient.stageOpenApplication(groupId, wrongProfile, sealed.message));
  const opened = recipient.stageOpenApplication(groupId, profile, sealed.message);
  equalBytes(opened.plaintext, bytes("opaque application frame"));
  equalBytes(opened.sender, founder.memberId());

  let third = new native.NativeClient(bytes("validated:third"));
  const thirdPackage = third.createKeyPackage(profile);
  third = native.NativeClient.fromSnapshot(thirdPackage.snapshot);
  const secondAdd = founder.stageAdd(groupId, profile, thirdPackage.keyPackage, authority, 102n);
  const applied = native.NativeClient.fromSnapshot(joined.snapshot)
    .stageApplyCommit(groupId, profile, secondAdd.commit, authority, 102n);
  assert.equal(applied.epoch, "2");

  assert.throws(() => native.NativeClient.fromSnapshot(new Uint8Array([...applied.snapshot, 0])));
  void third; // Confirms each package came from an independent local client.
});
