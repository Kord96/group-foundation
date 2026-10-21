//! Bounded native hooks for product adapters with their own authenticated MLS
//! profile. Product credential and extension validation stays with the adapter;
//! private signing custody and OpenMLS construction stay with Group.

use super::*;
use openmls_traits::signatures::{Signer, SignerError};

const SIGNING_STATE_MAGIC: &[u8; 5] = b"GFI01";
// Bound opaque TLS profile components without interpreting consumer policy.
pub const MAX_NATIVE_EXTENSION_BYTES: usize = 64 * 1024;
const MAX_NATIVE_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Product group custody. Immutable MLS inspection is available for a product's
/// authenticated profile validators; mutable state never leaves Group.
pub struct ProductGroup {
    inner: MlsGroup,
}

impl std::ops::Deref for ProductGroup {
    type Target = MlsGroup;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ProductGroup {
    /// Interpret an authenticated commit's resolved proposals against this
    /// parent group's local leaf. Public-only OpenMLS staging has no local
    /// membership and its private-state `self_removed` flag is not this fact.
    pub fn commit_removes_own_leaf(&self, commit: &StagedCommit) -> bool {
        let own_leaf = self.own_leaf_index();
        commit.queued_proposals().any(|item| match item.proposal() {
            Proposal::Remove(remove) => remove.removed() == own_leaf,
            Proposal::SelfRemove => {
                matches!(item.sender(), Sender::Member(leaf) if *leaf == own_leaf)
            }
            _ => false,
        })
    }
}

/// Opaque dictionary updates and product-selected membership changes. Products
/// authorize these before construction. Group checks allocation and key custody.
#[derive(Default)]
pub struct ProductCommitRequest {
    pub additions: Vec<KeyPackage>,
    pub removals: Vec<LeafNodeIndex>,
    pub component_updates: Vec<(u16, Option<Vec<u8>>)>,
    /// Exact TLS proposal references selected by the product. None includes all
    /// pending proposals; Some includes only this bounded set.
    pub proposal_references: Option<Vec<Vec<u8>>>,
}

pub struct ProductCommit {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

/// One detached local-signing-custody replacement.  The MLS Commit is signed
/// by the current leaf key while its UpdatePath installs the successor key.
/// The successor signer is returned only to the caller's detached custody; a
/// host still owns the atomic installation of that custody and its binding.
pub struct ProductSignerHandover {
    pub commit: Vec<u8>,
    pub successor: SigningIdentity,
}

#[derive(Clone, Copy)]
pub enum ProductMessageMode {
    Member,
    /// Verify an authored commit independently against the public parent. The
    /// product still compares the result with its retained pending candidate.
    OwnCommit,
    Application,
}

pub struct ProductMessageInfo {
    pub epoch: u64,
    pub handshake: bool,
}

impl ProductMessageInfo {
    pub fn inspect(bytes: &[u8]) -> Result<Self> {
        let message = product_protocol_message(bytes)?;
        Ok(Self {
            epoch: message.epoch().as_u64(),
            handshake: message.is_handshake_message(),
        })
    }
}

fn product_protocol_message(bytes: &[u8]) -> Result<ProtocolMessage> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_FRAME_BYTES {
        return Err(GroupError::Invalid("native message exceeds its bound"));
    }
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(mls)?
        .try_into_protocol_message()
        .map_err(mls)
}

/// Product-selected retention and receive-ratchet limits, checked before an
/// OpenMLS configuration is constructed. These are native resource limits,
/// independent of product governance or application history policy.
pub struct ProductJoinLimits {
    max_past_epochs: usize,
    out_of_order_tolerance: u32,
    max_forward_distance: u32,
}

impl ProductJoinLimits {
    pub fn new(
        max_past_epochs: usize,
        out_of_order_tolerance: u32,
        max_forward_distance: u32,
    ) -> Result<Self> {
        if max_past_epochs > 256 || out_of_order_tolerance > 256 || max_forward_distance > 4096 {
            return Err(GroupError::Invalid(
                "product ratchet or retention limits exceed native bounds",
            ));
        }
        Ok(Self {
            max_past_epochs,
            out_of_order_tolerance,
            max_forward_distance,
        })
    }
    fn config(&self) -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            // Every member can become the next committer. Preserve the same
            // self-contained Welcome contract used by product group creators;
            // a joined service must not emit an unjoinable third-member Welcome.
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.out_of_order_tolerance,
                self.max_forward_distance,
            ))
            .max_past_epochs(self.max_past_epochs)
            .build()
    }
}

/// Adapter-validated leaf and context hooks. Group applies only size limits and
/// MLS configuration; it never interprets the opaque product extension bytes.
pub struct ProductProfileHooks {
    config: MlsGroupCreateConfig,
}

impl ProductProfileHooks {
    pub fn new(
        capabilities: Capabilities,
        context: Extensions<GroupContext>,
        leaf: Extensions<LeafNode>,
        limits: ProductJoinLimits,
    ) -> Result<Self> {
        if capabilities.tls_serialize_detached().map_err(mls)?.len() > MAX_NATIVE_EXTENSION_BYTES
            || context.tls_serialize_detached().map_err(mls)?.len() > MAX_NATIVE_EXTENSION_BYTES
            || leaf.tls_serialize_detached().map_err(mls)?.len() > MAX_NATIVE_EXTENSION_BYTES
        {
            return Err(GroupError::Invalid(
                "product leaf or context extensions exceed native bounds",
            ));
        }
        Ok(Self {
            config: MlsGroupCreateConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .ciphersuite(GROUP_CIPHERSUITE)
                .capabilities(capabilities)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    limits.out_of_order_tolerance,
                    limits.max_forward_distance,
                ))
                .max_past_epochs(limits.max_past_epochs)
                .use_ratchet_tree_extension(true)
                .with_group_context_extensions(context)
                .with_leaf_node_extensions(leaf)
                .map_err(mls)?
                .build(),
        })
    }
}

/// Independently generated local MLS signing custody, without product evidence.
/// This key is independently generated and never derived from consumer secrets.
pub struct SigningIdentity {
    signer: SignatureKeyPair,
    seed: [u8; 32],
}

impl SigningIdentity {
    pub fn generate(provider: &Provider) -> Result<Self> {
        let mut seed = [0; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|_| GroupError::Invalid("secure random generation failed"))?;
        Self::from_seed(provider, seed)
    }

    pub fn from_seed(provider: &Provider, seed: [u8; 32]) -> Result<Self> {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            seed.to_vec(),
            key.verifying_key().to_bytes().to_vec(),
        );
        signer.store(provider.storage()).map_err(mls)?;
        Ok(Self { signer, seed })
    }

    /// Opaque local custody; the host must seal these bytes before persistence.
    pub fn export_state(&self) -> Vec<u8> {
        [SIGNING_STATE_MAGIC.as_slice(), &self.seed].concat()
    }

    pub fn from_state(provider: &Provider, encoded: &[u8]) -> Result<Self> {
        if encoded.len() != 37 || !encoded.starts_with(SIGNING_STATE_MAGIC) {
            return Err(GroupError::Invalid(
                "identity-key state header or version is invalid",
            ));
        }
        Self::from_seed(
            provider,
            encoded[5..].try_into().expect("checked seed width"),
        )
    }

    pub(crate) fn sealed_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public(&self) -> &[u8] {
        self.signer.public()
    }
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    fn remove_from(&self, provider: &Provider) -> Result<()> {
        SignatureKeyPair::delete(
            provider.storage(),
            self.signer.public(),
            self.signer.signature_scheme(),
        )
        .map_err(mls)
    }
}

impl Signer for SigningIdentity {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        self.signer.sign(payload)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl Provider {
    /// Validate native wire/signature structure before product credential checks.
    pub fn validate_product_key_package(bytes: &[u8]) -> Result<KeyPackage> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_EXTENSION_BYTES {
            return Err(GroupError::Invalid("native KeyPackage exceeds its bound"));
        }
        KeyPackageIn::tls_deserialize_exact(bytes)
            .map_err(mls)?
            .validate(Provider::new().crypto(), ProtocolVersion::Mls10)
            .map_err(mls)
    }

    pub fn product_key_package_reference(&self, package: &KeyPackage) -> Result<KeyPackageRef> {
        package.hash_ref(self.crypto()).map_err(mls)
    }

    fn require_product_signer(&self, group: &ProductGroup, signer: &SigningIdentity) -> Result<()> {
        if !group.is_active()
            || group
                .own_leaf_node()
                .is_none_or(|leaf| leaf.signature_key().as_slice() != signer.public())
        {
            return Err(GroupError::Invalid(
                "native signer is not the active local leaf",
            ));
        }
        Ok(())
    }

    pub fn prepare_product_commit(
        &self,
        group: &mut ProductGroup,
        signer: &SigningIdentity,
        request: ProductCommitRequest,
    ) -> Result<ProductCommit> {
        self.require_product_signer(group, signer)?;
        let count =
            request.additions.len() + request.removals.len() + request.component_updates.len();
        if count > 1024
            || request.proposal_references.as_ref().is_some_and(|refs| {
                refs.len() > 1024 || refs.iter().any(|r| r.is_empty() || r.len() > 128)
            })
        {
            return Err(GroupError::Invalid("native commit exceeds proposal bounds"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut update_bytes = 0usize;
        for (id, bytes) in &request.component_updates {
            update_bytes = update_bytes.saturating_add(bytes.as_ref().map_or(0, Vec::len));
            if !seen.insert(id) || update_bytes > MAX_NATIVE_EXTENSION_BYTES {
                return Err(GroupError::Invalid(
                    "duplicate or oversized native component update",
                ));
            }
        }
        if request.additions.iter().any(|kp| {
            kp.tls_serialize_detached()
                .map_or(true, |bytes| bytes.len() > MAX_NATIVE_EXTENSION_BYTES)
        }) {
            return Err(GroupError::Invalid("native KeyPackage exceeds its bound"));
        }
        let proposals: Vec<_> = request
            .component_updates
            .iter()
            .map(|(id, bytes)| {
                Proposal::AppDataUpdate(Box::new(match bytes {
                    Some(bytes) => AppDataUpdateProposal::update(*id, bytes.clone()),
                    None => AppDataUpdateProposal::remove(*id),
                }))
            })
            .collect();
        let mut builder = group
            .inner
            .commit_builder()
            .propose_adds(request.additions)
            .propose_removals(request.removals)
            .add_proposals(proposals)
            .load_psks(self.storage())
            .map_err(mls)?;
        let mut updater = builder.app_data_dictionary_updater();
        for (id, bytes) in request.component_updates {
            match bytes {
                Some(bytes) => updater.set(openmls::component::ComponentData::from_parts(
                    id,
                    bytes.into(),
                )),
                None => updater.remove(&id),
            }
        }
        builder.with_app_data_dictionary_updates(updater.changes());
        let (commit, welcome, _) = builder
            .build(self.rand(), self.crypto(), signer, |proposal| {
                request
                    .proposal_references
                    .as_ref()
                    .is_none_or(|references| {
                        proposal
                            .proposal_reference_ref()
                            .tls_serialize_detached()
                            .is_ok_and(|reference| references.contains(&reference))
                    })
            })
            .map_err(mls)?
            .stage_commit(self)
            .map_err(mls)?
            .into_contents();
        Ok(ProductCommit {
            commit: commit.to_bytes().map_err(mls)?,
            welcome: welcome
                .map(|welcome| {
                    MlsMessageOut::from_welcome(welcome, ProtocolVersion::Mls10)
                        .to_bytes()
                        .map_err(mls)
                })
                .transpose()?,
        })
    }

    /// Rotate the active local leaf to an independently prepared signing
    /// identity.  This is deliberately separate from generic membership
    /// changes: it cannot add/remove members or expose either private key.
    /// The operation runs on detached custody, commits no queued proposals,
    /// and removes the predecessor signer from the resulting provider.
    pub fn prepare_product_signer_handover(
        &self,
        group: &mut ProductGroup,
        predecessor: &SigningIdentity,
        successor: SigningIdentity,
        credential: CredentialWithKey,
    ) -> Result<ProductSignerHandover> {
        self.require_product_signer(group, predecessor)?;
        if predecessor.public() == successor.public() {
            return Err(GroupError::Invalid(
                "successor signing custody equals predecessor",
            ));
        }
        if credential.signature_key.as_slice() != successor.public() {
            return Err(GroupError::Invalid(
                "successor credential differs from signing custody",
            ));
        }
        let bundle = NewSignerBundle {
            signer: &successor,
            credential_with_key: credential,
        };
        let (commit, _, _) = group
            .inner
            .commit_builder()
            .load_psks(self.storage())
            .map_err(mls)?
            .build_with_new_signer(self.rand(), self.crypto(), predecessor, bundle, |_| false)
            .map_err(mls)?
            .stage_commit(self)
            .map_err(mls)?
            .into_contents();
        self.merge_product_pending(group)?;
        let local = group
            .members()
            .find(|member| member.index == group.own_leaf_index())
            .ok_or(GroupError::Invalid(
                "local member is absent after signer handover",
            ))?;
        if local.signature_key.as_slice() != successor.public() {
            return Err(GroupError::Invalid(
                "signer handover did not install successor leaf",
            ));
        }
        predecessor.remove_from(self)?;
        Ok(ProductSignerHandover {
            commit: commit.to_bytes().map_err(mls)?,
            successor,
        })
    }

    /// Authenticate and process opaque MLS bytes. The product callback checks
    /// component semantics before MLS applies the resulting dictionary. The
    /// callback must be pure: signature authentication completes afterward.
    /// Duplicate
    /// updates and missing referenced proposals fail before any commit is merged.
    /// Callers run on detached custody or restore a checkpoint on policy failure.
    pub fn process_product_message<E: From<GroupError>>(
        &self,
        group: &mut ProductGroup,
        bytes: &[u8],
        mode: ProductMessageMode,
        mut validate_component: impl FnMut(u16, Option<&[u8]>) -> std::result::Result<(), E>,
    ) -> std::result::Result<ProcessedMessage, E> {
        let message = product_protocol_message(bytes)?;
        if matches!(mode, ProductMessageMode::Application) && message.is_handshake_message() {
            return Err(GroupError::Invalid("native application intake rejects handshakes").into());
        }
        let unverified = group.inner.unprotect_message(self, message).map_err(mls)?;
        let mut updater = group.inner.app_data_dictionary_updater();
        if matches!(mode, ProductMessageMode::OwnCommit)
            && unverified.committed_proposals().is_none()
        {
            return Err(GroupError::Invalid("owned native message is not a commit").into());
        }
        if let Some(proposals) = unverified.committed_proposals() {
            let mut changed = std::collections::BTreeSet::new();
            let mut component_bytes = 0usize;
            for item in proposals {
                let proposal = match item
                    .clone()
                    .validate(self.crypto(), group.ciphersuite(), ProtocolVersion::Mls10)
                    .map_err(mls)?
                {
                    ProposalOrRef::Proposal(proposal) => proposal,
                    ProposalOrRef::Reference(reference) => Box::new(
                        group
                            .proposal_store()
                            .proposals()
                            .find(|p| p.proposal_reference_ref() == &*reference)
                            .ok_or(GroupError::Invalid("referenced native proposal is absent"))?
                            .proposal()
                            .clone(),
                    ),
                };
                if let Proposal::AppDataUpdate(update) = *proposal {
                    if !changed.insert(update.component_id()) || changed.len() > 1024 {
                        return Err(GroupError::Invalid(
                            "duplicate or excessive native component updates",
                        )
                        .into());
                    }
                    match update.operation() {
                        AppDataUpdateOperation::Update(bytes) => {
                            component_bytes =
                                component_bytes.saturating_add(bytes.as_slice().len());
                            if component_bytes > MAX_NATIVE_EXTENSION_BYTES {
                                return Err(GroupError::Invalid(
                                    "native component exceeds its bound",
                                )
                                .into());
                            }
                            validate_component(update.component_id(), Some(bytes.as_slice()))?;
                            updater.set(openmls::component::ComponentData::from_parts(
                                update.component_id(),
                                bytes.clone(),
                            ));
                        }
                        AppDataUpdateOperation::Remove => {
                            validate_component(update.component_id(), None)?;
                            updater.remove(&update.component_id());
                        }
                    }
                }
            }
        }
        let changes = updater.changes();
        match mode {
            ProductMessageMode::OwnCommit => {
                let public = self.public_product_group(group)?;
                public
                    .process_unverified_message_with_app_data_updates(
                        self.crypto(),
                        unverified,
                        changes,
                    )
                    .map_err(mls)
                    .map_err(Into::into)
            }
            _ => group
                .inner
                .process_unverified_message_with_app_data_updates(self, unverified, changes)
                .map_err(mls)
                .map_err(Into::into),
        }
    }

    pub fn public_product_group(
        &self,
        group: &ProductGroup,
    ) -> Result<openmls::group::PublicGroup> {
        openmls::group::PublicGroup::load(self.storage(), group.group_id())
            .map_err(mls)?
            .ok_or(GroupError::Invalid("native public group is absent"))
    }

    pub fn merge_product_pending(&self, group: &mut ProductGroup) -> Result<()> {
        group.inner.merge_pending_commit(self).map_err(mls)
    }

    pub fn merge_product_commit(
        &self,
        group: &mut ProductGroup,
        commit: StagedCommit,
    ) -> Result<()> {
        group.inner.merge_staged_commit(self, commit).map_err(mls)
    }

    pub fn store_product_proposal(
        &self,
        group: &mut ProductGroup,
        proposal: QueuedProposal,
    ) -> Result<()> {
        group
            .inner
            .store_pending_proposal(self.storage(), proposal)
            .map_err(mls)
    }

    pub fn product_self_remove(
        &self,
        group: &mut ProductGroup,
        signer: &SigningIdentity,
    ) -> Result<Vec<u8>> {
        self.require_product_signer(group, signer)?;
        group
            .inner
            .leave_group_via_self_remove(self, signer)
            .map_err(mls)?
            .to_bytes()
            .map_err(mls)
    }

    pub fn set_product_aad(&self, group: &mut ProductGroup, aad: Vec<u8>) -> Result<()> {
        if aad.len() > MAX_NATIVE_EXTENSION_BYTES {
            return Err(GroupError::Invalid("native AAD exceeds its bound"));
        }
        group.inner.set_aad(aad);
        Ok(())
    }

    pub fn delete_product_group(&self, group: &mut ProductGroup) -> Result<()> {
        group.inner.delete(self.storage()).map_err(mls)
    }

    /// Delete exactly one installed group's complete native namespace on a
    /// detached provider. Signing custody, KeyPackages, and product sidecars
    /// remain available to the product's atomic terminal transaction.
    pub fn stage_delete_product_group(&self, group_id: &[u8]) -> Result<Self> {
        let selected = self.detached()?;
        let mut group = selected
            .load_product_group(group_id)?
            .ok_or(GroupError::Invalid("product group absent"))?;
        selected.delete_product_group(&mut group)?;
        // OpenMLS deletes its current epoch keys. Retained epochs and pending
        // native records also belong to the terminal group's namespace.
        selected.prune_product_storage(group_id, |_| false)?;
        self.install_product_branch(self, &selected, group_id, |_| false)
    }

    /// Copy private MLS state for a detached product operation. Products copy
    /// their own sidecars separately and install both in one durable transaction.
    pub fn detached(&self) -> Result<Self> {
        Self::from_state(&self.export_state()?)
    }

    /// Validate the complete candidate before replacing live custody. A product
    /// uses this for rollback together with its own in-memory sidecars; durable
    /// installation still belongs to the host's transaction.
    pub fn restore_checkpoint(&self, encoded: &[u8]) -> Result<()> {
        let candidate = Self::from_state(encoded)?;
        let values = candidate
            .storage
            .values
            .into_inner()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        *self
            .storage
            .values
            .write()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))? = values;
        Ok(())
    }

    /// Load local state; the product must validate its authenticated profile
    /// before exposing the returned group to its policy or presentation layer.
    pub fn load_product_group(&self, group_id: &[u8]) -> Result<Option<ProductGroup>> {
        if group_id.is_empty() || group_id.len() > 255 {
            return Err(GroupError::Invalid("native group ID exceeds its bound"));
        }
        MlsGroup::load(self.storage(), &GroupId::from_slice(group_id))
            .map(|group| group.map(|inner| ProductGroup { inner }))
            .map_err(mls)
    }

    /// Stage Welcome decryption. Callers use detached custody and inspect the
    /// authenticated context/leaf through their product verifier before joining.
    pub fn stage_product_welcome(
        &self,
        limits: &ProductJoinLimits,
        welcome: Welcome,
    ) -> Result<StagedWelcome> {
        if welcome.tls_serialize_detached().map_err(mls)?.len() > MAX_NATIVE_FRAME_BYTES {
            return Err(GroupError::Invalid("native Welcome exceeds 4 MiB"));
        }
        StagedWelcome::new_from_welcome(self, &limits.config(), welcome, None).map_err(mls)
    }

    pub fn install_product_welcome(&self, staged: StagedWelcome) -> Result<ProductGroup> {
        if self
            .load_product_group(staged.group_context().group_id().as_slice())?
            .is_some()
        {
            return Err(GroupError::Invalid(
                "Welcome cannot replace an installed group",
            ));
        }
        staged
            .into_group(self)
            .map(|inner| ProductGroup { inner })
            .map_err(mls)
    }

    /// Seal adapter-validated application bytes with this group's current leaf.
    pub fn seal_product_application(
        &self,
        group: &mut ProductGroup,
        signer: &SigningIdentity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() > MAX_NATIVE_FRAME_BYTES {
            return Err(GroupError::Invalid(
                "native application payload exceeds its bound",
            ));
        }
        if !group.is_active()
            || group
                .own_leaf_node()
                .is_none_or(|leaf| leaf.signature_key().as_slice() != signer.public())
        {
            return Err(GroupError::Invalid(
                "native application signer is not the active local leaf",
            ));
        }
        group
            .inner
            .create_message(self, signer, plaintext)
            .map_err(mls)?
            .to_bytes()
            .map_err(mls)
    }

    /// The adapter owns label semantics and current-authority checks. Group
    /// bounds allocation and keeps derivation against its live native provider.
    pub fn export_product_secret(
        &self,
        group: &ProductGroup,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        if !group.is_active()
            || label.is_empty()
            || label.len() > 255
            || context.len() > MAX_EVIDENCE_BYTES
            || length == 0
            || length > MAX_EVIDENCE_BYTES
        {
            return Err(GroupError::Invalid(
                "native exporter input exceeds its bound or group is inactive",
            ));
        }
        group
            .export_secret(self.crypto(), label, context, length)
            .map_err(mls)
    }

    /// Create a group with a product-validated profile. Group bounds native
    /// context allocation and pins local signing custody and the cipher suite.
    pub fn create_product_group(
        &self,
        signer: &SigningIdentity,
        group_id: &[u8],
        credential: CredentialWithKey,
        profile: &ProductProfileHooks,
    ) -> Result<ProductGroup> {
        let config = &profile.config;
        if group_id.is_empty()
            || group_id.len() > 255
            || config.ciphersuite() != GROUP_CIPHERSUITE
            || credential.signature_key.as_slice() != signer.public()
            || credential.credential.serialized_content().len() > MAX_EVIDENCE_BYTES
            || config
                .group_context_extensions()
                .tls_serialize_detached()
                .map_err(mls)?
                .len()
                > MAX_NATIVE_EXTENSION_BYTES
        {
            return Err(GroupError::Invalid(
                "product group profile exceeds native bounds or changes signing custody",
            ));
        }
        if MlsGroup::load(self.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .is_some()
        {
            return Err(GroupError::Invalid("native group already installed"));
        }
        MlsGroup::new_with_group_id(
            self,
            signer,
            config,
            GroupId::from_slice(group_id),
            credential,
        )
        .map(|inner| ProductGroup { inner })
        .map_err(mls)
    }

    /// Build a fresh KeyPackage with adapter-validated opaque leaf extensions.
    /// Group pins the suite, credential key, and native allocation bounds.
    pub fn product_key_package(
        &self,
        signer: &SigningIdentity,
        credential: CredentialWithKey,
        capabilities: Capabilities,
        extensions: Extensions<LeafNode>,
    ) -> Result<KeyPackage> {
        if credential.signature_key.as_slice() != signer.public() {
            return Err(GroupError::Invalid(
                "product credential signing key differs from local custody",
            ));
        }
        if credential.credential.serialized_content().len() > MAX_EVIDENCE_BYTES
            || extensions.tls_serialize_detached().map_err(mls)?.len() > MAX_NATIVE_EXTENSION_BYTES
            || capabilities.tls_serialize_detached().map_err(mls)?.len()
                > MAX_NATIVE_EXTENSION_BYTES
        {
            return Err(GroupError::Invalid(
                "product KeyPackage profile exceeds native bounds",
            ));
        }
        Ok(KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .leaf_node_extensions(extensions)
            .build(GROUP_CIPHERSUITE, self, signer, credential)
            .map_err(mls)?
            .key_package()
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_product_deletion_removes_only_complete_selected_native_namespace() {
        let provider = Provider::new();
        let signer = SigningIdentity::generate(&provider).unwrap();
        let profile = ProductProfileHooks::new(
            Capabilities::default(),
            Extensions::default(),
            Extensions::default(),
            ProductJoinLimits::new(4, 4, 32).unwrap(),
        )
        .unwrap();
        let id = b"terminal-group";
        let mut group = provider
            .create_product_group(&signer, id, credential(&signer), &profile)
            .unwrap();
        provider
            .create_product_group(&signer, b"unrelated-group", credential(&signer), &profile)
            .unwrap();
        provider
            .product_key_package(
                &signer,
                credential(&signer),
                Capabilities::default(),
                Extensions::default(),
            )
            .unwrap();
        provider
            .store_product_record(b"group-foundation.sidecar.test.terminal", vec![1])
            .unwrap();
        provider
            .store_product_record(b"group-foundation.sidecar.test.unrelated", vec![2])
            .unwrap();
        provider
            .prepare_product_commit(&mut group, &signer, ProductCommitRequest::default())
            .unwrap();
        provider.merge_product_pending(&mut group).unwrap();
        provider
            .prepare_product_commit(&mut group, &signer, ProductCommitRequest::default())
            .unwrap();
        let before = provider.export_state().unwrap();
        let signing_before = signer.export_state();
        let selected = provider.stage_delete_product_group(id).unwrap();
        assert_eq!(provider.export_state().unwrap(), before);
        assert_eq!(signer.export_state(), signing_before);
        assert!(provider.load_product_group(id).unwrap().is_some());
        assert!(selected.load_product_group(id).unwrap().is_none());
        assert!(
            selected
                .load_product_group(b"unrelated-group")
                .unwrap()
                .is_some()
        );
        let expected: HashMap<_, _> = provider
            .storage
            .values
            .read()
            .unwrap()
            .iter()
            .filter(|(key, _)| !Provider::product_storage_is_owned(key, id).unwrap())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(*selected.storage.values.read().unwrap(), expected);
        for invalid in [b"".as_slice(), &[0; 256], b"absent", b"terminal-group"] {
            assert!(selected.stage_delete_product_group(invalid).is_err());
        }
        assert_eq!(provider.export_state().unwrap(), before);
    }

    #[test]
    fn joined_product_member_retains_tree_bearing_welcomes_after_reopen() {
        let creator = Provider::new();
        let creator_signer = SigningIdentity::generate(&creator).unwrap();
        let service = Provider::new();
        let service_signer = SigningIdentity::generate(&service).unwrap();
        let candidate = Provider::new();
        let candidate_signer = SigningIdentity::generate(&candidate).unwrap();
        let limits = || ProductJoinLimits::new(4, 4, 32).unwrap();
        let capabilities = || Capabilities::new(
            None, Some(&[GROUP_CIPHERSUITE]),
            Some(&[ExtensionType::AppDataDictionary]),
            Some(&[ProposalType::AppDataUpdate, ProposalType::SelfRemove]),
            Some(&[CredentialType::Basic]),
        );
        let profile = ProductProfileHooks::new(
            capabilities(), Extensions::single(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(AppDataDictionary::new()),
            )).unwrap(), Extensions::default(), limits(),
        ).unwrap();
        let mut group = creator.create_product_group(
            &creator_signer, b"joined-member-welcome", credential(&creator_signer), &profile,
        ).unwrap();
        let service_package = service.product_key_package(
            &service_signer, credential(&service_signer), capabilities(), Extensions::default(),
        ).unwrap();
        let initial = creator.prepare_product_commit(
            &mut group, &creator_signer,
            ProductCommitRequest { additions: vec![service_package], ..Default::default() },
        ).unwrap();
        let initial_welcome = MlsMessageIn::tls_deserialize_exact(&initial.welcome.unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(initial_welcome) = initial_welcome.extract() else {
            panic!("initial Welcome absent")
        };
        let staged = service.stage_product_welcome(&limits(), initial_welcome).unwrap();
        service.install_product_welcome(staged).unwrap();
        creator.merge_product_pending(&mut group).unwrap();
        // The committing member is a real joined member reopened from its own
        // private state, never a relabeled creator or a supplied public tree.
        let service = Provider::from_state(&service.export_state().unwrap()).unwrap();
        let mut service_group = service.load_product_group(b"joined-member-welcome").unwrap().unwrap();
        let candidate_package = candidate.product_key_package(
            &candidate_signer, credential(&candidate_signer), capabilities(), Extensions::default(),
        ).unwrap();
        let addition = service.prepare_product_commit(
            &mut service_group, &service_signer,
            ProductCommitRequest { additions: vec![candidate_package], ..Default::default() },
        ).unwrap();
        let welcome = MlsMessageIn::tls_deserialize_exact(&addition.welcome.unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("joined member Welcome absent")
        };
        // stage_product_welcome supplies no detached ratchet tree. OpenMLS must
        // authenticate the tree actually carried by this genuine Welcome.
        let staged = candidate.stage_product_welcome(&limits(), welcome).unwrap();
        let candidate_group = candidate.install_product_welcome(staged).unwrap();
        service.merge_product_pending(&mut service_group).unwrap();
        assert_eq!(candidate_group.epoch(), service_group.epoch());
        assert_eq!(candidate_group.inner.members().count(), 3);
        assert_eq!(candidate_group.inner.export_ratchet_tree(), service_group.inner.export_ratchet_tree());
    }

    #[test]
    fn product_transitions_authenticate_opaque_updates_and_keep_application_intake_separate() {
        let provider = Provider::new();
        let signer = SigningIdentity::generate(&provider).unwrap();
        let recipient_provider = Provider::new();
        let recipient_signer = SigningIdentity::generate(&recipient_provider).unwrap();
        let capabilities = || {
            Capabilities::new(
                None,
                Some(&[GROUP_CIPHERSUITE]),
                Some(&[ExtensionType::AppDataDictionary]),
                Some(&[ProposalType::AppDataUpdate, ProposalType::SelfRemove]),
                Some(&[CredentialType::Basic]),
            )
        };
        let context = || {
            Extensions::single(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(AppDataDictionary::new()),
            ))
            .unwrap()
        };
        let limits = || ProductJoinLimits::new(4, 4, 32).unwrap();
        let profile =
            ProductProfileHooks::new(capabilities(), context(), Extensions::default(), limits())
                .unwrap();
        let mut group = provider
            .create_product_group(
                &signer,
                b"opaque-transitions",
                credential(&signer),
                &profile,
            )
            .unwrap();
        let kp = recipient_provider
            .product_key_package(
                &recipient_signer,
                credential(&recipient_signer),
                capabilities(),
                Extensions::default(),
            )
            .unwrap();
        let add = provider
            .prepare_product_commit(
                &mut group,
                &signer,
                ProductCommitRequest {
                    additions: vec![kp],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(group.epoch().as_u64(), 0);
        assert!(!authenticated_public_removal(
            &provider,
            &mut group,
            &add.commit
        ));
        let welcome = MlsMessageIn::tls_deserialize_exact(&add.welcome.unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("Welcome absent")
        };
        let staged = recipient_provider
            .stage_product_welcome(&limits(), welcome)
            .unwrap();
        let mut recipient = recipient_provider.install_product_welcome(staged).unwrap();
        provider.merge_product_pending(&mut group).unwrap();
        let before = provider.export_state().unwrap();
        assert!(
            provider
                .prepare_product_commit(
                    &mut group,
                    &recipient_signer,
                    ProductCommitRequest::default()
                )
                .is_err()
        );
        assert!(
            provider
                .prepare_product_commit(
                    &mut group,
                    &signer,
                    ProductCommitRequest {
                        component_updates: vec![(42, Some(vec![1])), (42, Some(vec![2]))],
                        ..Default::default()
                    }
                )
                .is_err()
        );
        assert_eq!(provider.export_state().unwrap(), before);
        let commit = provider
            .prepare_product_commit(
                &mut group,
                &signer,
                ProductCommitRequest {
                    component_updates: vec![(42, Some(b"product-owned semantics".to_vec()))],
                    ..Default::default()
                },
            )
            .unwrap()
            .commit;
        assert!(!authenticated_public_removal(
            &provider, &mut group, &commit
        ));
        let mut called = false;
        assert!(
            recipient_provider
                .process_product_message::<GroupError>(
                    &mut recipient,
                    &commit,
                    ProductMessageMode::Application,
                    |_, _| {
                        called = true;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert!(!called);
        assert!(
            recipient_provider
                .process_product_message::<GroupError>(
                    &mut recipient,
                    &commit,
                    ProductMessageMode::Member,
                    |_, _| Err(GroupError::Invalid("product rejects component"))
                )
                .is_err()
        );
        assert_eq!(recipient.epoch().as_u64(), 1);
        let processed = recipient_provider
            .process_product_message::<GroupError>(
                &mut recipient,
                &commit,
                ProductMessageMode::Member,
                |component, bytes| {
                    assert_eq!(component, 42);
                    assert_eq!(bytes, Some(b"product-owned semantics".as_slice()));
                    Ok(())
                },
            )
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("commit absent")
        };
        recipient_provider
            .merge_product_commit(&mut recipient, *staged)
            .unwrap();
        provider.merge_product_pending(&mut group).unwrap();
        let application = provider
            .seal_product_application(&mut group, &signer, b"opaque application")
            .unwrap();
        let processed = recipient_provider
            .process_product_message::<GroupError>(
                &mut recipient,
                &application,
                ProductMessageMode::Application,
                |_, _| Ok(()),
            )
            .unwrap();
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            panic!("application absent")
        };
        assert_eq!(application.into_bytes(), b"opaque application");

        // A terminal dictionary update removing another member retains the
        // author's leaf, while the removed member sees its own exact removal.
        let removal_provider = provider.detached().unwrap();
        let mut removal_group = removal_provider
            .load_product_group(group.group_id().as_slice())
            .unwrap()
            .unwrap();
        let removal = removal_provider
            .prepare_product_commit(
                &mut removal_group,
                &signer,
                ProductCommitRequest {
                    removals: vec![recipient.own_leaf_index()],
                    component_updates: vec![(42, Some(b"opaque terminal state".to_vec()))],
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(!authenticated_public_removal(
            &removal_provider,
            &mut removal_group,
            &removal.commit
        ));
        assert!(authenticated_public_removal(
            &recipient_provider,
            &mut recipient,
            &removal.commit
        ));

        let leave = recipient_provider
            .product_self_remove(&mut recipient, &recipient_signer)
            .unwrap();
        for (local_provider, local_group) in [
            (&provider, &mut group),
            (&recipient_provider, &mut recipient),
        ] {
            let message = local_provider
                .process_product_message::<GroupError>(
                    local_group,
                    &leave,
                    ProductMessageMode::Member,
                    |_, _| Ok(()),
                )
                .unwrap();
            let ProcessedMessageContent::ProposalMessage(proposal) = message.into_content() else {
                panic!("SelfRemove proposal absent")
            };
            local_provider
                .store_product_proposal(local_group, *proposal)
                .unwrap();
        }
        let leave_commit = provider
            .prepare_product_commit(&mut group, &signer, ProductCommitRequest::default())
            .unwrap();
        assert!(!authenticated_public_removal(
            &provider,
            &mut group,
            &leave_commit.commit
        ));
        assert!(authenticated_public_removal(
            &recipient_provider,
            &mut recipient,
            &leave_commit.commit
        ));
    }

    fn authenticated_public_removal(
        provider: &Provider,
        group: &mut ProductGroup,
        commit: &[u8],
    ) -> bool {
        let before = provider.export_state().unwrap();
        let processed = provider
            .process_product_message::<GroupError>(
                group,
                commit,
                ProductMessageMode::OwnCommit,
                |_, _| Ok(()),
            )
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("commit absent")
        };
        let removed = group.commit_removes_own_leaf(&staged);
        assert_eq!(provider.export_state().unwrap(), before);
        removed
    }

    #[test]
    fn local_signer_handover_is_detached_restartable_and_exact() {
        let provider = Provider::new();
        let predecessor = SigningIdentity::generate(&provider).unwrap();
        let peer_provider = Provider::new();
        let peer_signer = SigningIdentity::generate(&peer_provider).unwrap();
        let profile = ProductProfileHooks::new(
            Capabilities::default(),
            Extensions::default(),
            Extensions::default(),
            ProductJoinLimits::new(4, 4, 32).unwrap(),
        )
        .unwrap();
        let group_id = b"signer-handover";
        let mut group = provider
            .create_product_group(&predecessor, group_id, credential(&predecessor), &profile)
            .unwrap();
        let peer_package = peer_provider
            .product_key_package(
                &peer_signer,
                credential(&peer_signer),
                Capabilities::default(),
                Extensions::default(),
            )
            .unwrap();
        let add = provider
            .prepare_product_commit(
                &mut group,
                &predecessor,
                ProductCommitRequest {
                    additions: vec![peer_package],
                    ..Default::default()
                },
            )
            .unwrap();
        let welcome = MlsMessageIn::tls_deserialize_exact(add.welcome.unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("Welcome absent")
        };
        let staged_peer = peer_provider
            .stage_product_welcome(&ProductJoinLimits::new(4, 4, 32).unwrap(), welcome)
            .unwrap();
        let mut peer = peer_provider.install_product_welcome(staged_peer).unwrap();
        provider.merge_product_pending(&mut group).unwrap();

        let source_before = provider.export_state().unwrap();
        let selected = provider.detached().unwrap();
        let mut selected_group = selected.load_product_group(group_id).unwrap().unwrap();
        let successor = SigningIdentity::generate(&selected).unwrap();
        let successor_state = successor.export_state();
        let predecessor_key = predecessor.to_public_vec();
        let successor_key = successor.to_public_vec();
        selected
            .set_product_aad(&mut selected_group, b"authorized signer handover".to_vec())
            .unwrap();
        let handover = selected
            .prepare_product_signer_handover(
                &mut selected_group,
                &predecessor,
                successor,
                CredentialWithKey {
                    credential: BasicCredential::new(b"successor evidence".to_vec()).into(),
                    signature_key: successor_key.clone().into(),
                },
            )
            .unwrap();
        assert_eq!(provider.export_state().unwrap(), source_before);
        assert_eq!(handover.successor.public(), successor_key);
        assert!(
            SignatureKeyPair::read(
                selected.storage(),
                &predecessor_key,
                SignatureScheme::ED25519
            )
            .is_none()
        );
        assert!(
            SignatureKeyPair::read(selected.storage(), &successor_key, SignatureScheme::ED25519)
                .is_some()
        );
        let local = selected_group
            .members()
            .find(|member| member.index == selected_group.own_leaf_index())
            .unwrap();
        assert_eq!(local.signature_key.as_slice(), successor_key);
        assert_eq!(selected_group.epoch().as_u64(), 2);

        let restarted_provider = Provider::from_state(&selected.export_state().unwrap()).unwrap();
        let restarted_signer =
            SigningIdentity::from_state(&restarted_provider, &successor_state).unwrap();
        let mut restarted_group = restarted_provider
            .load_product_group(group_id)
            .unwrap()
            .unwrap();
        restarted_provider
            .seal_product_application(&mut restarted_group, &restarted_signer, b"after restart")
            .unwrap();

        let processed = peer_provider
            .process_product_message::<GroupError>(
                &mut peer,
                &handover.commit,
                ProductMessageMode::Member,
                |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(processed.aad(), b"authorized signer handover");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("handover commit absent")
        };
        peer_provider
            .merge_product_commit(&mut peer, *staged)
            .unwrap();
        assert_eq!(peer.epoch().as_u64(), 2);
        assert_eq!(
            peer.members()
                .find(|member| member.index == selected_group.own_leaf_index())
                .unwrap()
                .signature_key
                .as_slice(),
            successor_key
        );
    }

    #[test]
    fn local_signer_handover_rejects_substitution_without_live_effects() {
        let provider = Provider::new();
        let predecessor = SigningIdentity::generate(&provider).unwrap();
        let profile = ProductProfileHooks::new(
            Capabilities::default(),
            Extensions::default(),
            Extensions::default(),
            ProductJoinLimits::new(4, 4, 32).unwrap(),
        )
        .unwrap();
        let group_id = b"signer-handover-attacks";
        provider
            .create_product_group(&predecessor, group_id, credential(&predecessor), &profile)
            .unwrap();
        let source_before = provider.export_state().unwrap();

        let same = provider.detached().unwrap();
        let mut same_group = same.load_product_group(group_id).unwrap().unwrap();
        let same_signer = SigningIdentity::from_state(&same, &predecessor.export_state()).unwrap();
        assert!(
            same.prepare_product_signer_handover(
                &mut same_group,
                &predecessor,
                same_signer,
                credential(&predecessor)
            )
            .is_err()
        );

        let changed = provider.detached().unwrap();
        let mut changed_group = changed.load_product_group(group_id).unwrap().unwrap();
        let successor = SigningIdentity::generate(&changed).unwrap();
        assert!(
            changed
                .prepare_product_signer_handover(
                    &mut changed_group,
                    &predecessor,
                    successor,
                    credential(&predecessor)
                )
                .is_err()
        );
        let mut malformed = predecessor.export_state();
        malformed[0] ^= 1;
        assert!(SigningIdentity::from_state(&provider, &malformed).is_err());
        assert_eq!(provider.export_state().unwrap(), source_before);
    }

    #[test]
    fn product_context_bounds_allow_bounded_components_and_reject_oversized_hooks() {
        let context = |length| {
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(PROFILE_COMPONENT, vec![0; length]);
            Extensions::single(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dictionary),
            ))
            .unwrap()
        };
        assert!(
            ProductProfileHooks::new(
                Capabilities::default(),
                context(20 * 1024),
                Extensions::default(),
                ProductJoinLimits::new(64, 32, 1024).unwrap()
            )
            .is_ok()
        );
        assert!(
            ProductProfileHooks::new(
                Capabilities::default(),
                context(MAX_NATIVE_EXTENSION_BYTES),
                Extensions::default(),
                ProductJoinLimits::new(64, 32, 1024).unwrap()
            )
            .is_err()
        );
    }

    fn credential(signer: &SigningIdentity) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(b"opaque product evidence".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        }
    }

    #[test]
    fn product_hooks_fence_local_keys_and_restore_opaque_checkpoints() {
        let provider = Provider::new();
        let signer = SigningIdentity::generate(&provider).unwrap();
        let wrong_signer = SigningIdentity::generate(&provider).unwrap();
        let checkpoint = provider.export_state().unwrap();
        let config = ProductProfileHooks::new(
            Capabilities::default(),
            Extensions::default(),
            Extensions::default(),
            ProductJoinLimits::new(0, 0, 0).unwrap(),
        )
        .unwrap();
        assert!(
            provider
                .product_key_package(
                    &signer,
                    credential(&wrong_signer),
                    Capabilities::default(),
                    Extensions::default()
                )
                .is_err()
        );
        assert!(
            provider
                .create_product_group(&signer, b"hook-group", credential(&wrong_signer), &config)
                .is_err()
        );
        let mut group = provider
            .create_product_group(&signer, b"hook-group", credential(&signer), &config)
            .unwrap();
        assert!(
            provider
                .create_product_group(&signer, b"hook-group", credential(&signer), &config)
                .is_err()
        );
        assert!(
            provider
                .seal_product_application(&mut group, &wrong_signer, b"opaque frame")
                .is_err()
        );
        assert!(
            !provider
                .seal_product_application(&mut group, &signer, b"opaque frame")
                .unwrap()
                .is_empty()
        );
        assert!(
            provider
                .export_product_secret(&group, "", b"context", 32)
                .is_err()
        );
        assert!(
            provider
                .export_product_secret(&group, "product", b"context", MAX_EVIDENCE_BYTES + 1)
                .is_err()
        );
        let exported = provider
            .export_product_secret(&group, "product", b"context", 32)
            .unwrap();
        assert_eq!(exported.len(), 32);
        let detached = provider.detached().unwrap();
        let before_failed_restore = provider.export_state().unwrap();
        assert!(provider.restore_checkpoint(b"invalid checkpoint").is_err());
        assert_eq!(provider.export_state().unwrap(), before_failed_restore);
        provider.restore_checkpoint(&checkpoint).unwrap();
        assert!(
            provider
                .load_product_group(b"hook-group")
                .unwrap()
                .is_none()
        );
        assert!(
            detached
                .load_product_group(b"hook-group")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn provider_snapshot_rejects_duplicate_keys_and_unbounded_lengths() {
        let duplicate = [
            b"GFS01".as_slice(),
            &2_u64.to_be_bytes(),
            &1_u64.to_be_bytes(),
            &0_u64.to_be_bytes(),
            b"a",
            &1_u64.to_be_bytes(),
            &0_u64.to_be_bytes(),
            b"a",
        ]
        .concat();
        assert!(Provider::from_state(&duplicate).is_err());
        let huge_length = [
            b"GFS01".as_slice(),
            &1_u64.to_be_bytes(),
            &u64::MAX.to_be_bytes(),
            &0_u64.to_be_bytes(),
        ]
        .concat();
        assert!(Provider::from_state(&huge_length).is_err());
        let provider = Provider::new();
        provider
            .storage
            .values
            .write()
            .unwrap()
            .insert(vec![0; MAX_PROVIDER_KEY_BYTES + 1], vec![]);
        assert!(provider.export_state().is_err());
    }

    #[test]
    fn local_signing_custody_is_exact_and_independent() {
        let provider = Provider::new();
        let identity = SigningIdentity::generate(&provider).unwrap();
        let other = SigningIdentity::generate(&provider).unwrap();
        assert_ne!(identity.public(), other.public());
        let encoded = identity.export_state();
        assert_eq!(
            SigningIdentity::from_state(&provider, &encoded)
                .unwrap()
                .public(),
            identity.public()
        );
        assert!(SigningIdentity::from_state(&provider, &encoded[..36]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(SigningIdentity::from_state(&provider, &trailing).is_err());
        let mut wrong_version = encoded;
        wrong_version[4] = 2;
        assert!(SigningIdentity::from_state(&provider, &wrong_version).is_err());
    }
}
