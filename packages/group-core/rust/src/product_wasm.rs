//! Browser product boundary. All mutations run on detached custody; returned
//! facts are MLS authenticated and product semantics remain with the caller.
use super::*;
use js_sys::{Array, Object, Reflect, Uint8Array};
use openmls_traits::signatures::Signer;
use wasm_bindgen::{JsCast, prelude::*};

const MAGIC: &[u8; 5] = b"GFC01";
const MAX_FRAME: usize = 4 * 1024 * 1024;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export interface ProductLimits { maxPastEpochs: number; outOfOrderTolerance: number; maxForwardDistance: number; }
/** Exact MLS TLS encodings, interpreted only by OpenMLS. */
export interface ProductProfile extends ProductLimits { capabilities: Uint8Array; contextExtensions: Uint8Array; leafExtensions: Uint8Array; }
export interface ProductMember { leaf: number; signingKey: Uint8Array; credential: Uint8Array; components: Uint8Array; leafNode: Uint8Array; }
export interface ProductProposal { proposal: Uint8Array; origin: 'inline' | 'reference'; reference?: Uint8Array; sender: Uint8Array; }
export interface ProductProjection { groupId: Uint8Array; epoch: string; active: boolean; ownLeaf: number; members: ProductMember[]; components: Uint8Array; context: Uint8Array; ratchetTree: Uint8Array; pendingProposals: ProductProposal[]; }
export interface ProductStage { custody: Uint8Array; projection: ProductProjection; }
export interface ProductKeyPackageStage { custody: Uint8Array; keyPackage: Uint8Array; reference: Uint8Array; leafNode: Uint8Array; }
export interface ProductComponentUpdate { id: number; value: Uint8Array | null; }
export interface ProductCommitRequest { additions: Uint8Array[]; removals: number[]; componentUpdates: ProductComponentUpdate[]; proposalReferences?: Uint8Array[]; }
export interface ProductCommitStage extends ProductStage { commit: Uint8Array; welcome?: Uint8Array; pendingCustody: Uint8Array; }
export interface ProductMessageStage extends ProductStage { kind: 'commit' | 'proposal' | 'application'; sender: Uint8Array; credential: Uint8Array; aad: Uint8Array; messageEpoch: string; componentUpdates: ProductComponentUpdate[]; proposals: ProductProposal[]; plaintext?: Uint8Array; resultingContext?: Uint8Array; selfRemoved?: boolean; }
export interface ProductFrameStage extends ProductStage { frame: Uint8Array; }
export interface ProductRecord { key: Uint8Array; value: Uint8Array | null; }
export interface ProductSignerProof { signingKey: Uint8Array; signature: Uint8Array; }
"#;

fn error(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}
fn object() -> JsValue {
    Object::new().into()
}
fn set(target: &JsValue, name: &str, value: &JsValue) -> std::result::Result<(), JsError> {
    Reflect::set(target, &name.into(), value)
        .map(|_| ())
        .map_err(|_| error("cannot construct product result"))
}
fn bytes(target: &JsValue, name: &str, value: &[u8]) -> std::result::Result<(), JsError> {
    set(target, name, &Uint8Array::from(value).into())
}
fn tls<T: openmls::prelude::tls_codec::Serialize>(
    value: &T,
) -> std::result::Result<Vec<u8>, JsError> {
    value.tls_serialize_detached().map_err(error)
}
fn field(value: &JsValue, name: &str) -> std::result::Result<JsValue, JsError> {
    Reflect::get(value, &name.into()).map_err(|_| error("invalid product input field"))
}
fn input_bytes(value: JsValue, max: usize) -> std::result::Result<Vec<u8>, JsError> {
    let array = value
        .dyn_into::<Uint8Array>()
        .map_err(|_| error("product bytes must be Uint8Array"))?;
    if array.length() as usize > max {
        return Err(error("product bytes exceed bound"));
    }
    Ok(array.to_vec())
}
fn number(value: JsValue, max: u32) -> std::result::Result<u32, JsError> {
    let n = value
        .as_f64()
        .ok_or_else(|| error("product integer required"))?;
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > max as f64 {
        return Err(error("product integer exceeds bound"));
    }
    Ok(n as u32)
}
fn array(value: JsValue) -> std::result::Result<Array, JsError> {
    if !Array::is_array(&value) {
        return Err(error("product array required"));
    }
    let result = value.unchecked_into::<Array>();
    if result.length() > 1024 {
        return Err(error("product array exceeds bound"));
    }
    Ok(result)
}
fn limits(value: &JsValue) -> std::result::Result<ProductJoinLimits, JsError> {
    ProductJoinLimits::new(
        number(field(value, "maxPastEpochs")?, 256)? as usize,
        number(field(value, "outOfOrderTolerance")?, 256)?,
        number(field(value, "maxForwardDistance")?, 4096)?,
    )
    .map_err(error)
}
fn profile(value: &JsValue) -> std::result::Result<ProductProfileHooks, JsError> {
    ProductProfileHooks::new(
        Capabilities::tls_deserialize_exact(&input_bytes(
            field(value, "capabilities")?,
            MAX_NATIVE_EXTENSION_BYTES,
        )?)
        .map_err(error)?,
        Extensions::tls_deserialize_exact(&input_bytes(
            field(value, "contextExtensions")?,
            MAX_NATIVE_EXTENSION_BYTES,
        )?)
        .map_err(error)?,
        Extensions::tls_deserialize_exact(&input_bytes(
            field(value, "leafExtensions")?,
            MAX_NATIVE_EXTENSION_BYTES,
        )?)
        .map_err(error)?,
        limits(value)?,
    )
    .map_err(error)
}
fn proposal(value: &QueuedProposal) -> std::result::Result<JsValue, JsError> {
    let out = object();
    bytes(&out, "proposal", &tls(value.proposal())?)?;
    match value.proposal_or_ref_type() {
        ProposalOrRefType::Proposal => set(&out, "origin", &"inline".into())?,
        ProposalOrRefType::Reference => {
            set(&out, "origin", &"reference".into())?;
            bytes(&out, "reference", &tls(value.proposal_reference_ref())?)?;
        }
    }
    bytes(&out, "sender", &tls(value.sender())?)?;
    Ok(out)
}
fn projection(
    provider: &Provider,
    group: &ProductGroup,
    signer: &SigningIdentity,
) -> std::result::Result<JsValue, JsError> {
    let public = provider.public_product_group(group).map_err(error)?;
    if group.is_active()
        && group
            .own_leaf_node()
            .is_none_or(|leaf| leaf.signature_key().as_slice() != signer.public())
    {
        return Err(error("product custody signer differs from local leaf"));
    }
    let out = object();
    bytes(&out, "groupId", group.group_id().as_slice())?;
    set(&out, "epoch", &group.epoch().as_u64().to_string().into())?;
    set(&out, "active", &group.is_active().into())?;
    set(&out, "ownLeaf", &group.own_leaf_index().u32().into())?;
    bytes(&out, "components", &tls(group.extensions())?)?;
    bytes(&out, "context", &tls(public.group_context())?)?;
    bytes(&out, "ratchetTree", &tls(&group.export_ratchet_tree())?)?;
    let members = Array::new();
    for member in group.members() {
        let leaf = public
            .leaf(member.index)
            .ok_or_else(|| error("authenticated leaf absent"))?;
        let item = object();
        set(&item, "leaf", &member.index.u32().into())?;
        bytes(&item, "signingKey", &member.signature_key)?;
        bytes(&item, "credential", &tls(&member.credential)?)?;
        bytes(&item, "components", &tls(leaf.extensions())?)?;
        bytes(&item, "leafNode", &tls(leaf)?)?;
        members.push(&item);
    }
    set(&out, "members", &members.into())?;
    let proposals = Array::new();
    for item in group.pending_proposals() {
        proposals.push(&proposal(item)?);
    }
    set(&out, "pendingProposals", &proposals.into())?;
    Ok(out)
}

/// Independently generated MLS signing custody plus a bounded in-memory provider.
/// Callers seal exported custody and atomically install it with product sidecars.
#[wasm_bindgen]
pub struct NativeProductClient {
    provider: Provider,
    signer: SigningIdentity,
}

#[wasm_bindgen]
impl NativeProductClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> std::result::Result<Self, JsError> {
        let provider = Provider::new();
        let signer = SigningIdentity::generate(&provider).map_err(error)?;
        Ok(Self { provider, signer })
    }
    #[wasm_bindgen(js_name = fromParts)]
    pub fn from_parts(
        provider_state: &[u8],
        signing_state: &[u8],
    ) -> std::result::Result<Self, JsError> {
        let provider = Provider::from_state(provider_state).map_err(error)?;
        let signer = SigningIdentity::from_state(&provider, signing_state).map_err(error)?;
        Ok(Self { provider, signer })
    }
    #[wasm_bindgen(js_name = fromCustody)]
    pub fn from_custody(custody: &[u8]) -> std::result::Result<Self, JsError> {
        if custody.len() < 9
            || custody.len() > MAX_PROVIDER_STATE_BYTES + 46
            || !custody.starts_with(MAGIC)
        {
            return Err(error("invalid product custody header or size"));
        }
        let size = u32::from_be_bytes(custody[5..9].try_into().expect("checked header")) as usize;
        if size > MAX_PROVIDER_STATE_BYTES || custody.len() != 9 + size + 37 {
            return Err(error("truncated or trailing product custody"));
        }
        Self::from_parts(&custody[9..9 + size], &custody[9 + size..])
    }
    #[wasm_bindgen(js_name = exportCustody)]
    pub fn export_custody(&self) -> std::result::Result<Vec<u8>, JsError> {
        let state = self.provider.export_state().map_err(error)?;
        let mut out = Vec::with_capacity(46 + state.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(state.len() as u32).to_be_bytes());
        out.extend_from_slice(&state);
        out.extend_from_slice(&self.signer.export_state());
        Ok(out)
    }
    #[wasm_bindgen(js_name = exportProviderState)]
    pub fn export_provider_state(&self) -> std::result::Result<Vec<u8>, JsError> {
        self.provider.export_state().map_err(error)
    }
    #[wasm_bindgen(js_name = exportSigningState)]
    pub fn export_signing_state(&self) -> Vec<u8> {
        self.signer.export_state()
    }
    #[wasm_bindgen(js_name = ownSigner)]
    pub fn own_signer(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }
    #[wasm_bindgen(js_name = signProof, unchecked_return_type = "ProductSignerProof")]
    pub fn sign_proof(&self, transcript: &[u8]) -> std::result::Result<JsValue, JsError> {
        if transcript.is_empty() || transcript.len() > MAX_EVIDENCE_BYTES {
            return Err(error("product proof transcript exceeds bound"));
        }
        let out = object();
        bytes(&out, "signingKey", self.signer.public())?;
        bytes(
            &out,
            "signature",
            &self
                .signer
                .sign(transcript)
                .map_err(|_| error("product proof signing failed"))?,
        )?;
        Ok(out)
    }
    #[wasm_bindgen(unchecked_return_type = "ProductProjection")]
    pub fn inspect(&self, group_id: &[u8]) -> std::result::Result<JsValue, JsError> {
        projection(&self.provider, &self.group(group_id)?, &self.signer)
    }
    /// Distinguishes a deleted group from an installed inactive group. Invalid
    /// IDs, malformed native state, and active signer mismatches still fail.
    #[wasm_bindgen(js_name = hasGroup)]
    pub fn has_group(&self, group_id: &[u8]) -> std::result::Result<bool, JsError> {
        let Some(group) = self.provider.load_product_group(group_id).map_err(error)? else {
            for key in self
                .provider
                .storage
                .values
                .read()
                .map_err(|_| error("provider storage lock poisoned"))?
                .keys()
            {
                if Provider::product_storage_is_owned(key, group_id).map_err(error)? {
                    return Err(error("absent product group retains native records"));
                }
            }
            return Ok(false);
        };
        projection(&self.provider, &group, &self.signer)?;
        Ok(true)
    }
    /// Returns custody with only the selected group's native state removed.
    /// Product sidecar deletion is staged separately with exact record keys.
    #[wasm_bindgen(js_name = stageDelete)]
    pub fn stage_delete(&self, group_id: &[u8]) -> std::result::Result<Vec<u8>, JsError> {
        self.inspect(group_id)?;
        let provider = self
            .provider
            .stage_delete_product_group(group_id)
            .map_err(error)?;
        Self::from_parts(
            &provider.export_state().map_err(error)?,
            &self.signer.export_state(),
        )?
        .export_custody()
    }
    /// Credential is an exact MLS Credential TLS encoding, never private key material.
    #[wasm_bindgen(js_name = stageCreate, unchecked_return_type = "ProductStage")]
    pub fn stage_create(
        &self,
        group_id: &[u8],
        credential: &[u8],
        #[wasm_bindgen(unchecked_param_type = "ProductProfile")] config: JsValue,
    ) -> std::result::Result<JsValue, JsError> {
        let next = self.detached()?;
        let group = next
            .provider
            .create_product_group(
                &next.signer,
                group_id,
                next.credential(credential)?,
                &profile(&config)?,
            )
            .map_err(error)?;
        next.result(&group)
    }
    #[wasm_bindgen(js_name = stageKeyPackage, unchecked_return_type = "ProductKeyPackageStage")]
    pub fn stage_key_package(
        &self,
        credential: &[u8],
        #[wasm_bindgen(unchecked_param_type = "ProductProfile")] config: JsValue,
    ) -> std::result::Result<JsValue, JsError> {
        let next = self.detached()?;
        let capabilities = Capabilities::tls_deserialize_exact(&input_bytes(
            field(&config, "capabilities")?,
            MAX_NATIVE_EXTENSION_BYTES,
        )?)
        .map_err(error)?;
        let extensions = Extensions::tls_deserialize_exact(&input_bytes(
            field(&config, "leafExtensions")?,
            MAX_NATIVE_EXTENSION_BYTES,
        )?)
        .map_err(error)?;
        let package = next
            .provider
            .product_key_package(
                &next.signer,
                next.credential(credential)?,
                capabilities,
                extensions,
            )
            .map_err(error)?;
        let out = object();
        bytes(&out, "custody", &next.export_custody()?)?;
        bytes(&out, "keyPackage", &tls(&package)?)?;
        bytes(
            &out,
            "reference",
            &tls(&next
                .provider
                .product_key_package_reference(&package)
                .map_err(error)?)?,
        )?;
        bytes(&out, "leafNode", &tls(package.leaf_node())?)?;
        Ok(out)
    }
    #[wasm_bindgen(js_name = stageJoin, unchecked_return_type = "ProductStage")]
    pub fn stage_join(
        &self,
        welcome: &[u8],
        #[wasm_bindgen(unchecked_param_type = "ProductLimits")] config: JsValue,
    ) -> std::result::Result<JsValue, JsError> {
        if welcome.is_empty() || welcome.len() > MAX_FRAME {
            return Err(error("product Welcome exceeds bound"));
        }
        let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(error)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(error("product join requires Welcome"));
        };
        let next = self.detached()?;
        let staged = next
            .provider
            .stage_product_welcome(&limits(&config)?, welcome)
            .map_err(error)?;
        let group = next
            .provider
            .install_product_welcome(staged)
            .map_err(error)?;
        next.result(&group)
    }
    /// Returns both the exact pending custody and its merged candidate. Neither is installed.
    #[wasm_bindgen(js_name = stageCommit, unchecked_return_type = "ProductCommitStage")]
    pub fn stage_commit(
        &self,
        group_id: &[u8],
        #[wasm_bindgen(unchecked_param_type = "ProductCommitRequest")] request: JsValue,
        aad: Vec<u8>,
    ) -> std::result::Result<JsValue, JsError> {
        let mut parsed = ProductCommitRequest::default();
        let mut total = 0usize;
        for value in array(field(&request, "additions")?)?.iter() {
            let encoded = input_bytes(value, MAX_NATIVE_EXTENSION_BYTES)?;
            total += encoded.len();
            if total > MAX_FRAME {
                return Err(error("product additions exceed bound"));
            }
            parsed
                .additions
                .push(Provider::validate_product_key_package(&encoded).map_err(error)?);
        }
        for value in array(field(&request, "removals")?)?.iter() {
            parsed
                .removals
                .push(LeafNodeIndex::new(number(value, u32::MAX)?));
        }
        let mut component_bytes = 0usize;
        for value in array(field(&request, "componentUpdates")?)?.iter() {
            let id = number(field(&value, "id")?, u16::MAX as u32)? as u16;
            let data = field(&value, "value")?;
            let data = if data.is_null() {
                None
            } else {
                Some(input_bytes(data, MAX_NATIVE_EXTENSION_BYTES)?)
            };
            component_bytes += data.as_ref().map_or(0, Vec::len);
            if component_bytes > MAX_NATIVE_EXTENSION_BYTES {
                return Err(error("product component updates exceed bound"));
            }
            parsed.component_updates.push((id, data));
        }
        let refs = field(&request, "proposalReferences")?;
        if !refs.is_undefined() {
            parsed.proposal_references = Some(
                array(refs)?
                    .iter()
                    .map(|v| input_bytes(v, 128))
                    .collect::<std::result::Result<_, _>>()?,
            );
        }
        let next = self.detached()?;
        let mut group = next.group(group_id)?;
        if let Some(references) = &parsed.proposal_references {
            let available = group
                .pending_proposals()
                .map(|item| tls(item.proposal_reference_ref()))
                .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
            let mut seen = std::collections::BTreeSet::new();
            for reference in references {
                if !seen.insert(reference) || !available.contains(reference) {
                    return Err(error(
                        "selected product proposal reference is duplicate or absent",
                    ));
                }
            }
        }
        next.provider
            .set_product_aad(&mut group, aad)
            .map_err(error)?;
        let commit = next
            .provider
            .prepare_product_commit(&mut group, &next.signer, parsed)
            .map_err(error)?;
        let pending = next.export_custody()?;
        next.provider
            .merge_product_pending(&mut group)
            .map_err(error)?;
        let out = next.result(&group)?;
        bytes(&out, "pendingCustody", &pending)?;
        bytes(&out, "commit", &commit.commit)?;
        if let Some(welcome) = commit.welcome {
            bytes(&out, "welcome", &welcome)?;
        }
        Ok(out)
    }
    #[wasm_bindgen(js_name = stageMergePending, unchecked_return_type = "ProductStage")]
    pub fn stage_merge_pending(&self, group_id: &[u8]) -> std::result::Result<JsValue, JsError> {
        let next = self.detached()?;
        let mut group = next.group(group_id)?;
        next.provider
            .merge_product_pending(&mut group)
            .map_err(error)?;
        next.result(&group)
    }
    /// Mode is member, application, or ownCommit. Component updates and proposal
    /// facts are returned only after full MLS authentication. ownCommit verifies
    /// against the public parent and returns no advanced private ratchet state.
    #[wasm_bindgen(js_name = stageProcess, unchecked_return_type = "ProductMessageStage")]
    pub fn stage_process(
        &self,
        group_id: &[u8],
        frame: &[u8],
        #[wasm_bindgen(unchecked_param_type = "'member' | 'application' | 'ownCommit'")] mode: &str,
    ) -> std::result::Result<JsValue, JsError> {
        let mode = match mode {
            "member" => ProductMessageMode::Member,
            "application" => ProductMessageMode::Application,
            "ownCommit" => ProductMessageMode::OwnCommit,
            _ => return Err(error("invalid product message mode")),
        };
        let next = self.detached()?;
        let mut group = next.group(group_id)?;
        let mut updates = Vec::new();
        let processed = next
            .provider
            .process_product_message::<GroupError>(&mut group, frame, mode, |id, data| {
                updates.push((id, data.map(<[u8]>::to_vec)));
                Ok(())
            })
            .map_err(error)?;
        let out = object();
        bytes(&out, "sender", &tls(processed.sender())?)?;
        bytes(&out, "credential", &tls(processed.credential())?)?;
        bytes(&out, "aad", processed.aad())?;
        set(
            &out,
            "messageEpoch",
            &processed.epoch().as_u64().to_string().into(),
        )?;
        let proposals = Array::new();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                set(&out, "kind", &"application".into())?;
                bytes(&out, "plaintext", &message.into_bytes())?;
            }
            ProcessedMessageContent::ProposalMessage(item)
            | ProcessedMessageContent::ExternalJoinProposalMessage(item) => {
                set(&out, "kind", &"proposal".into())?;
                proposals.push(&proposal(&item)?);
                next.provider
                    .store_product_proposal(&mut group, *item)
                    .map_err(error)?;
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                set(&out, "kind", &"commit".into())?;
                bytes(&out, "resultingContext", &tls(commit.group_context())?)?;
                let self_removed = if matches!(mode, ProductMessageMode::OwnCommit) {
                    group.commit_removes_own_leaf(&commit)
                } else {
                    commit.self_removed()
                };
                set(&out, "selfRemoved", &self_removed.into())?;
                for item in commit.queued_proposals() {
                    proposals.push(&proposal(item)?);
                }
                if !matches!(mode, ProductMessageMode::OwnCommit) {
                    next.provider
                        .merge_product_commit(&mut group, *commit)
                        .map_err(error)?;
                }
            }
        }
        let changed = Array::new();
        for (id, data) in updates {
            let item = object();
            set(&item, "id", &JsValue::from(id))?;
            match data {
                Some(data) => bytes(&item, "value", &data)?,
                None => set(&item, "value", &JsValue::NULL)?,
            };
            changed.push(&item);
        }
        set(&out, "componentUpdates", &changed.into())?;
        set(&out, "proposals", &proposals.into())?;
        bytes(&out, "custody", &next.export_custody()?)?;
        set(
            &out,
            "projection",
            &projection(&next.provider, &group, &next.signer)?,
        )?;
        Ok(out)
    }
    #[wasm_bindgen(js_name = stageSeal, unchecked_return_type = "ProductFrameStage")]
    pub fn stage_seal(
        &self,
        group_id: &[u8],
        plaintext: &[u8],
        aad: Vec<u8>,
    ) -> std::result::Result<JsValue, JsError> {
        let next = self.detached()?;
        let mut group = next.group(group_id)?;
        next.provider
            .set_product_aad(&mut group, aad)
            .map_err(error)?;
        let frame = next
            .provider
            .seal_product_application(&mut group, &next.signer, plaintext)
            .map_err(error)?;
        let out = next.result(&group)?;
        bytes(&out, "frame", &frame)?;
        Ok(out)
    }
    #[wasm_bindgen(js_name = stageSelfRemove, unchecked_return_type = "ProductFrameStage")]
    pub fn stage_self_remove(
        &self,
        group_id: &[u8],
        aad: Vec<u8>,
    ) -> std::result::Result<JsValue, JsError> {
        let next = self.detached()?;
        let mut group = next.group(group_id)?;
        next.provider
            .set_product_aad(&mut group, aad)
            .map_err(error)?;
        let frame = next
            .provider
            .product_self_remove(&mut group, &next.signer)
            .map_err(error)?;
        let out = next.result(&group)?;
        bytes(&out, "frame", &frame)?;
        Ok(out)
    }
    #[wasm_bindgen(js_name = exportSecret)]
    pub fn export_secret(
        &self,
        group_id: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> std::result::Result<Vec<u8>, JsError> {
        self.provider
            .export_product_secret(&self.group(group_id)?, label, context, length)
            .map_err(error)
    }
    #[wasm_bindgen(js_name = readRecord)]
    pub fn read_record(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, JsError> {
        self.provider.product_record(key).map_err(error)
    }
    /// Sidecar changes share the same opaque custody checkpoint as MLS state.
    #[wasm_bindgen(js_name = stageRecords)]
    pub fn stage_records(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ProductRecord[]")] records: JsValue,
    ) -> std::result::Result<Vec<u8>, JsError> {
        let next = self.detached()?;
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0;
        for record in array(records)?.iter() {
            let key = input_bytes(field(&record, "key")?, MAX_PROVIDER_KEY_BYTES)?;
            total += key.len();
            if total > MAX_PROVIDER_STATE_BYTES {
                return Err(error("product record keys exceed bound"));
            }
            if !seen.insert(key.clone()) {
                return Err(error("duplicate product record key"));
            }
            let value = field(&record, "value")?;
            if value.is_null() {
                next.provider.product_record(&key).map_err(error)?;
                next.provider
                    .storage
                    .values
                    .write()
                    .map_err(|_| error("provider lock poisoned"))?
                    .remove(&key);
            } else {
                let value = input_bytes(value, MAX_PROVIDER_STATE_BYTES)?;
                total += value.len();
                if total > MAX_PROVIDER_STATE_BYTES {
                    return Err(error("product records exceed bound"));
                }
                next.provider
                    .store_product_record(&key, value)
                    .map_err(error)?;
            }
        }
        next.export_custody()
    }
    /// Installs only the selected group's native records and exact product keys.
    /// Foreign mutations and signing custody substitutions are rejected.
    #[wasm_bindgen(js_name = stageCheckpoint)]
    pub fn stage_checkpoint(
        &self,
        anchor: &[u8],
        selected: &[u8],
        group_id: &[u8],
        #[wasm_bindgen(unchecked_param_type = "Uint8Array[]")] sidecar_keys: JsValue,
    ) -> std::result::Result<Vec<u8>, JsError> {
        let anchor = Self::from_custody(anchor)?;
        let selected = Self::from_custody(selected)?;
        if anchor.signer.public() != self.signer.public()
            || selected.signer.public() != self.signer.public()
        {
            return Err(error("checkpoint signing custody differs"));
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for key in array(sidecar_keys)?.iter() {
            let key = input_bytes(key, MAX_PROVIDER_KEY_BYTES)?;
            total += key.len();
            if total > MAX_PROVIDER_STATE_BYTES {
                return Err(error("checkpoint sidecar keys exceed bound"));
            }
            self.provider.product_record(&key).map_err(error)?;
            if !keys.insert(key) {
                return Err(error("duplicate checkpoint sidecar"));
            }
        }
        let provider = self
            .provider
            .install_product_branch(&anchor.provider, &selected.provider, group_id, |key| {
                keys.contains(key)
            })
            .map_err(error)?;
        let candidate = Self::from_parts(
            &provider.export_state().map_err(error)?,
            &self.signer.export_state(),
        )?;
        if !candidate.has_group(group_id)? {
            // Absence is a terminal transition from the exact installed anchor,
            // never evidence that an unknown or partially erased group settled.
            anchor.inspect(group_id)?;
        }
        candidate.export_custody()
    }
}
impl NativeProductClient {
    fn detached(&self) -> std::result::Result<Self, JsError> {
        Self::from_custody(&self.export_custody()?)
    }
    fn group(&self, id: &[u8]) -> std::result::Result<ProductGroup, JsError> {
        self.provider
            .load_product_group(id)
            .map_err(error)?
            .ok_or_else(|| error("product group absent"))
    }
    fn credential(&self, encoded: &[u8]) -> std::result::Result<CredentialWithKey, JsError> {
        if encoded.is_empty() || encoded.len() > MAX_EVIDENCE_BYTES + 8 {
            return Err(error("product credential exceeds bound"));
        }
        Ok(CredentialWithKey {
            credential: Credential::tls_deserialize_exact(encoded).map_err(error)?,
            signature_key: self.signer.to_public_vec().into(),
        })
    }
    fn result(&self, group: &ProductGroup) -> std::result::Result<JsValue, JsError> {
        let out = object();
        bytes(&out, "custody", &self.export_custody()?)?;
        set(
            &out,
            "projection",
            &projection(&self.provider, group, &self.signer)?,
        )?;
        Ok(out)
    }
}
