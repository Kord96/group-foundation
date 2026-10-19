import {BouncerError} from './contracts.js';
import type {
 BouncerClaimDisclosureV1,BouncerClaimRequestV1,BouncerDecisionV1,BouncerEvidenceInputV1,
 BouncerEvidenceRequestDefinitionV1,BouncerEvidenceRequestV1,BouncerSignedEvidenceDecisionV1,
 BouncerSignedEvidenceVerifierV1,ClaimEvidenceV1,ClaimPolicyV1,EvidenceRequestBindingV1,Sha256Port,
} from './contracts.js';
import {digest} from './digest.js';
import {assertEvidenceRequestBindingV1,claimEvidenceSatisfiesV1,equalEvidenceRequestBindingV1,parseClaimPolicyV1} from './policy.js';
import {parseBouncerDecisionV1,parseBouncerEvidenceRequestDefinitionV1,parseBouncerEvidenceRequestV1,parseClaimEvidenceV1,parseEvidenceRequestBindingV1,wireArray,wireInteger} from './wire.js';

const fail=():never=>{throw new BouncerError();};
const guarded=async<T>(operation:()=>T|Promise<T>):Promise<T>=>{try{return await operation();}catch{return fail();}};

function requestId(value:BouncerEvidenceRequestDefinitionV1,sha256:Sha256Port):Promise<string>{
 const binding=value.binding;
 return digest('group-foundation.bouncer-evidence-request.v1\0'+JSON.stringify([
  value.schema,binding.scopeId,binding.policyId,binding.policyRevision,binding.policyDigest,
  binding.target,binding.recipient,binding.audience,binding.purpose,binding.subjectCommitment,binding.nonce,
  value.issuedAt,value.expiresAt,value.claims.map(claim=>[claim.claimId,claim.disclosure.assertion,claim.disclosure.rawValue,claim.disclosure.scopedIdentifier]),
 ]),sha256);
}

function evidenceDigest(value:readonly ClaimEvidenceV1[],sha256:Sha256Port):Promise<string>{
 const canonical=[...value].sort((left,right)=>left.claimId<right.claimId?-1:left.claimId>right.claimId?1:0).map(item=>[
  item.claimId,item.assertion??null,item.value??null,item.privateIdentifier??null,item.verifiedAt,item.verificationExpiresAt,
  item.verificationMethod,item.verificationIssuer??null,item.issuedAt,item.expiresAt,
 ]);
 return digest('group-foundation.bouncer-evidence.v1\0'+JSON.stringify(canonical),sha256);
}

type DecisionDefinition=BouncerDecisionV1 extends infer D?D extends BouncerDecisionV1?Omit<D,'decisionId'>:never:never;
function decisionId(value:DecisionDefinition,sha256:Sha256Port):Promise<string>{
 const binding=value.binding;
 return digest('group-foundation.bouncer-decision.v1\0'+JSON.stringify([
  value.schema,value.outcome,value.requestId,binding.scopeId,binding.policyId,binding.policyRevision,binding.policyDigest,
  binding.target,binding.recipient,binding.audience,binding.purpose,binding.subjectCommitment,binding.nonce,
  value.policyId,value.policyRevision,value.policyDigest,value.evidenceDigest,value.requestIssuedAt,value.requestExpiresAt,value.evaluatedAt,
  value.outcome==='approved'?[value.evidenceFreshUntil,value.disclosures.map(item=>[item.claimId,item.assertion??null,item.value??null,item.privateIdentifier??null])]:[value.reason],
 ]),sha256);
}

async function freezeDecision(value:DecisionDefinition,sha256:Sha256Port):Promise<Readonly<BouncerDecisionV1>>{
 return Object.freeze({...value,decisionId:await decisionId(value,sha256)}) as Readonly<BouncerDecisionV1>;
}

function assertRequestedClaims(request:BouncerEvidenceRequestV1|BouncerEvidenceRequestDefinitionV1,policy:ClaimPolicyV1):void{
 const requested=new Set(request.claims.map(claim=>claim.claimId));
 if(policy.claims.some(claim=>claim.required&&!requested.has(claim.claimId))||request.claims.some(claim=>{
  const rule=policy.claims.find(item=>item.claimId===claim.claimId);
  return !rule||(['assertion','rawValue','scopedIdentifier'] as const).some(key=>claim.disclosure[key]&&!rule.disclosure[key]);
 }))return fail();
}

/** Construct a canonical policy-pinned request, valid for at most 900 seconds. */
export async function createBouncerEvidenceRequestV1(value:BouncerEvidenceRequestDefinitionV1,policy:ClaimPolicyV1,sha256:Sha256Port):Promise<Readonly<BouncerEvidenceRequestV1>>{
 return guarded(async()=>{const request=parseBouncerEvidenceRequestDefinitionV1(value),current=await assertEvidenceRequestBindingV1(policy,request.binding,sha256);assertRequestedClaims(request,current);return Object.freeze({...request,requestId:await requestId(request,sha256)});});
}

/** Verify only the canonical digest; this does not establish the host's expected scope. */
export async function verifyBouncerEvidenceRequestIntegrityV1(value:unknown,sha256:Sha256Port):Promise<Readonly<BouncerEvidenceRequestV1>>{
 return guarded(async()=>{const request=parseBouncerEvidenceRequestV1(value);if(request.requestId!==await requestId(request,sha256))return fail();return request;});
}

/** Require an exact host binding, current policy pin, authorized claims and freshness. */
export async function assertBouncerEvidenceRequestV1(value:unknown,policy:ClaimPolicyV1,binding:EvidenceRequestBindingV1,now:number,sha256:Sha256Port):Promise<Readonly<BouncerEvidenceRequestV1>>{
 return guarded(async()=>{const expected=parseEvidenceRequestBindingV1(binding),request=await verifyBouncerEvidenceRequestIntegrityV1(value,sha256),current=await assertEvidenceRequestBindingV1(policy,request.binding,sha256);if(!equalEvidenceRequestBindingV1(expected,request.binding)||!wireInteger(now)||now<request.issuedAt||now>=request.expiresAt)return fail();assertRequestedClaims(request,current);return request;});
}

function outputDisclosure(request:BouncerClaimRequestV1,evidence:ClaimEvidenceV1):Readonly<BouncerClaimDisclosureV1>{
 if(Object.hasOwn(evidence,'assertion')!==request.disclosure.assertion||Object.hasOwn(evidence,'value')!==request.disclosure.rawValue||Object.hasOwn(evidence,'privateIdentifier')!==request.disclosure.scopedIdentifier)return fail();
 return Object.freeze({claimId:request.claimId,...(evidence.assertion===true?{assertion:true as const}:{}),...(evidence.value===undefined?{}:{value:evidence.value}),...(evidence.privateIdentifier===undefined?{}:{privateIdentifier:evidence.privateIdentifier})});
}

/** Evaluate authenticated evidence and return an immutable fact only. */
export async function evaluateBouncerEvidenceV1(input:Readonly<{request:unknown;policy:ClaimPolicyV1;binding:EvidenceRequestBindingV1;evidence:readonly BouncerEvidenceInputV1[];now:number;}>,sha256:Sha256Port):Promise<Readonly<BouncerDecisionV1>>{
 return guarded(async()=>{
  const evidence=wireArray(input.evidence).map(parseClaimEvidenceV1),rawRequest=parseBouncerEvidenceRequestV1(input.request),binding=parseEvidenceRequestBindingV1(input.binding),policy=await parseClaimPolicyV1(input.policy,sha256),request=await verifyBouncerEvidenceRequestIntegrityV1(rawRequest,sha256);
  await assertEvidenceRequestBindingV1(policy,request.binding,sha256);
  if(!equalEvidenceRequestBindingV1(binding,request.binding)||!wireInteger(input.now))return fail();
  assertRequestedClaims(request,policy);
  const base={schema:'group-foundation.bouncer-decision.v1' as const,requestId:request.requestId,binding:request.binding,policyId:policy.policyId,policyRevision:policy.revision,policyDigest:policy.digest,evidenceDigest:await evidenceDigest(evidence,sha256),requestIssuedAt:request.issuedAt,requestExpiresAt:request.expiresAt,evaluatedAt:input.now};
  const byId=new Map<string,ClaimEvidenceV1>();let duplicate=false;
  for(const item of evidence){if(byId.has(item.claimId))duplicate=true;byId.set(item.claimId,item);}
  const complete=!duplicate&&evidence.length===request.claims.length&&request.claims.every(claim=>{
   const item=byId.get(claim.claimId);return item!==undefined&&Object.hasOwn(item,'assertion')===claim.disclosure.assertion&&Object.hasOwn(item,'value')===claim.disclosure.rawValue&&Object.hasOwn(item,'privateIdentifier')===claim.disclosure.scopedIdentifier;
  })&&input.now>=request.issuedAt&&input.now<request.expiresAt&&claimEvidenceSatisfiesV1(policy,evidence,input.now);
  if(!complete)return freezeDecision({...base,outcome:'denied',reason:'evidence-requirements-not-satisfied'},sha256);
  const disclosures=Object.freeze(request.claims.map(claim=>outputDisclosure(claim,byId.get(claim.claimId)!)));
  const evidenceFreshUntil=Math.min(request.expiresAt,...evidence.map(item=>{const rule=policy.claims.find(claim=>claim.claimId===item.claimId)!;return Math.min(item.expiresAt,item.verificationExpiresAt,item.verifiedAt+rule.verification.maximumAgeSeconds);}));
  if(!wireInteger(evidenceFreshUntil)||evidenceFreshUntil<=input.now)return fail();
  return freezeDecision({...base,outcome:'approved',evidenceFreshUntil,disclosures},sha256);
 });
}

/** Verify the subject first, then each signed claim against the exact request. */
export async function verifyBouncerSignedEvidenceV1<TPresentation,TEvidence>(input:Readonly<{policy:ClaimPolicyV1;binding:EvidenceRequestBindingV1;claims:readonly BouncerClaimRequestV1[];presentation:unknown;evidence:readonly unknown[];now:number;verifier:BouncerSignedEvidenceVerifierV1<TPresentation,TEvidence>;}>,sha256:Sha256Port):Promise<Readonly<BouncerSignedEvidenceDecisionV1<TPresentation,TEvidence>>>{
 return guarded(async()=>{
  const {now,presentation:rawPresentation,verifier}=input,binding=parseEvidenceRequestBindingV1(input.binding),evidence=[...wireArray(input.evidence)],claims=parseBouncerEvidenceRequestDefinitionV1({schema:'group-foundation.bouncer-evidence-request.v1',binding,issuedAt:0,expiresAt:1,claims:input.claims}).claims;
  if(!wireInteger(now)||typeof verifier?.verifyPresentation!=='function'||typeof verifier?.verifyEvidence!=='function')return fail();
  const policy=await assertEvidenceRequestBindingV1(input.policy,binding,sha256),presentation=await verifier.verifyPresentation(rawPresentation,binding);
  if(!presentation||typeof presentation!=='object'||!Object.hasOwn(presentation,'value')||!wireInteger(presentation.issuedAt)||!wireInteger(presentation.expiresAt)||presentation.issuedAt>now||presentation.expiresAt<=now)return fail();
  const request=await createBouncerEvidenceRequestV1({schema:'group-foundation.bouncer-evidence-request.v1',binding,issuedAt:presentation.issuedAt,expiresAt:Math.min(presentation.expiresAt,presentation.issuedAt+900),claims},policy,sha256),verified:{evidence:ClaimEvidenceV1;value:TEvidence}[]=[];
  for(const value of evidence){const result=await verifier.verifyEvidence(value,{request,policy,now});if(!result||typeof result!=='object'||!Object.hasOwn(result,'evidence')||!Object.hasOwn(result,'value'))return fail();verified.push({evidence:parseClaimEvidenceV1(result.evidence),value:result.value});}
  const decision=await evaluateBouncerEvidenceV1({request,policy,binding,evidence:verified.map(item=>item.evidence),now},sha256);
  return Object.freeze({request,decision,presentation:presentation.value,evidence:Object.freeze(verified.map(item=>item.value))});
 });
}

/** Authenticate retained decision data against the exact request and policy. */
export async function assertBouncerDecisionV1(input:Readonly<{request:unknown;policy:ClaimPolicyV1;binding:EvidenceRequestBindingV1;decision:unknown;now:number;}>,sha256:Sha256Port):Promise<Readonly<BouncerDecisionV1>>{
 return guarded(async()=>{
  const decision=parseBouncerDecisionV1(input.decision),binding=parseEvidenceRequestBindingV1(input.binding),policy=await parseClaimPolicyV1(input.policy,sha256),request=await verifyBouncerEvidenceRequestIntegrityV1(input.request,sha256);
  await assertEvidenceRequestBindingV1(policy,request.binding,sha256);
  if(!wireInteger(input.now)||decision.evaluatedAt>input.now||decision.requestId!==request.requestId||!equalEvidenceRequestBindingV1(decision.binding,request.binding)||!equalEvidenceRequestBindingV1(binding,request.binding)||decision.policyId!==policy.policyId||decision.policyRevision!==policy.revision||decision.policyDigest!==policy.digest||decision.requestIssuedAt!==request.issuedAt||decision.requestExpiresAt!==request.expiresAt||decision.outcome==='approved'&&input.now>=decision.evidenceFreshUntil)return fail();
  const {decisionId:claimed,...definition}=decision;if(claimed!==await decisionId(definition,sha256))return fail();return decision;
 });
}
