//! Neutral, product-independent MLS group mechanics.
//!
//! This crate deliberately has no account, alias, route, audience, history, or
//! role model.  A product supplies opaque credential evidence and implements
//! the two ports below.  MLS signing keys, KeyPackage private keys, ratchets,
//! and provider storage remain locally generated and are never derived from
//! product secrets.

use std::{collections::HashMap, sync::RwLock};

use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod product;
mod product_storage;
pub use product_storage::SIDECAR_PREFIX;
#[cfg(feature = "wasm")]
mod product_wasm;
pub use product::{
    MAX_NATIVE_EXTENSION_BYTES, ProductCommit, ProductCommitRequest, ProductGroup,
    ProductJoinLimits, ProductMessageInfo, ProductMessageMode, ProductProfileHooks,
    ProductSignerHandover, SigningIdentity,
};
#[cfg(feature = "wasm")]
pub use product_wasm::NativeProductClient;

/// The suite is deliberately fixed by this first Group profile.  A product
/// that needs another suite defines a new profile; it cannot silently change
/// the suite of an existing group.
pub const GROUP_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const MAX_PROFILE_BYTES: usize = 4 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
pub const MAX_PROVIDER_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROVIDER_ENTRIES: usize = 4096;
pub const MAX_PROVIDER_KEY_BYTES: usize = 64 * 1024;
pub const MAX_APPLICATION_BYTES: usize = 1024 * 1024;

const PROFILE_COMPONENT: openmls::component::ComponentId = 0xff00;
const PROVIDER_MAGIC: &[u8; 5] = b"GFS01";
const MEMBER_ID_DOMAIN: &[u8] = b"group-foundation.group.member-id.v1\0";

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("MLS operation failed: {0}")]
    Mls(String),
    #[error("identity verification failed: {0}")]
    Identity(String),
    #[error("governance authorization failed: {0}")]
    Governance(String),
}

type Result<T> = std::result::Result<T, GroupError>;

fn mls<T: std::fmt::Display>(error: T) -> GroupError {
    GroupError::Mls(error.to_string())
}

/// An opaque product profile, pinned in the authenticated MLS GroupContext
/// and repeated in every leaf.  The bytes are product-defined but canonical
/// encoding is required so byte equality is the profile equality relation.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GroupProfile(Vec<u8>);

impl GroupProfile {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
            return Err(GroupError::Invalid("group profile must be 1..=4096 bytes"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// SHA-256 fingerprint of an independently generated MLS Ed25519 signing
/// key.  It is the Group member identifier; it is not a product account ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MemberId([u8; 32]);

impl MemberId {
    pub fn from_signing_key(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(GroupError::Invalid("MLS signing key must be 32 bytes"));
        }
        let mut hasher = Sha256::new();
        hasher.update(MEMBER_ID_DOMAIN);
        hasher.update(key);
        Ok(Self(hasher.finalize().into()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The product credential carried in the BasicCredential plus the MLS key
/// fingerprint to which it is bound.  The evidence is opaque to Group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberBinding {
    pub member_id: MemberId,
    /// Public MLS signing key whose fingerprint is `member_id`.  Product
    /// verifiers receive it to check their evidence's exact MLS-key binding.
    pub mls_signing_key: [u8; 32],
    pub evidence: Vec<u8>,
}

impl MemberBinding {
    pub fn new(mls_signing_key: [u8; 32], evidence: impl Into<Vec<u8>>) -> Result<Self> {
        let evidence = evidence.into();
        validate_evidence(&evidence)?;
        Ok(Self {
            member_id: MemberId::from_signing_key(&mls_signing_key)?,
            mls_signing_key,
            evidence,
        })
    }
}

fn validate_evidence(evidence: &[u8]) -> Result<()> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_BYTES {
        return Err(GroupError::Invalid(
            "member evidence must be 1..=16384 bytes",
        ));
    }
    Ok(())
}

/// Product-owned verification result.  A revision and deadline deliberately
/// accompany successful verification so a product can fence stale authority
/// decisions when a detached result is physically committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityGrant {
    pub revision: u64,
    pub valid_until: u64,
}

impl AuthorityGrant {
    pub fn current_at(self, now: u64) -> Result<Self> {
        if self.valid_until < now {
            return Err(GroupError::Identity("authority grant has expired".into()));
        }
        Ok(self)
    }
}

/// Product-owned identity verifier.  It verifies credential evidence, scope,
/// proof-of-possession policy, validity, and revocation.  MLS itself verifies
/// the KeyPackage and leaf signatures before this port is invoked.
pub trait IdentityPort {
    fn verify_member(
        &self,
        profile: &GroupProfile,
        binding: &MemberBinding,
        now: u64,
    ) -> std::result::Result<AuthorityGrant, String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernanceAction {
    Add,
    Remove,
    ApplyCommit,
    SealApplication,
}

/// A small authenticated snapshot supplied to governance.  It exposes only
/// neutral MLS facts, never aliases, roles, routes, or product policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupFacts {
    pub group_id: Vec<u8>,
    pub profile: GroupProfile,
    pub epoch: u64,
    pub members: Vec<MemberBinding>,
}

/// Product-owned governance.  Group calls it before a transition and again
/// immediately before returning detached durable state.  Products use the
/// revision/deadline to reject an authority decision that changed mid-flight.
pub trait GovernancePort {
    fn authorize(
        &self,
        action: GovernanceAction,
        facts: &GroupFacts,
        actor: MemberId,
        target: Option<MemberId>,
        now: u64,
    ) -> std::result::Result<AuthorityGrant, String>;
}

/// OpenMLS provider storage owned by one local client.  The exported format is
/// opaque, bounded, deterministic, and includes MLS private state; callers
/// must seal it and commit it atomically with their product records.
#[derive(Default)]
pub struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl Provider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn export_state(&self) -> Result<Vec<u8>> {
        let values = self
            .storage
            .values
            .read()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        if values.len() > MAX_PROVIDER_ENTRIES {
            return Err(GroupError::Invalid("provider has too many entries"));
        }
        let mut rows: Vec<_> = values.iter().collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = Vec::with_capacity(5 + 8);
        out.extend_from_slice(PROVIDER_MAGIC);
        out.extend_from_slice(&(rows.len() as u64).to_be_bytes());
        for (key, value) in rows {
            if key.len() > MAX_PROVIDER_KEY_BYTES || value.len() > MAX_PROVIDER_STATE_BYTES {
                return Err(GroupError::Invalid("provider entry exceeds size limit"));
            }
            let next = out
                .len()
                .checked_add(16)
                .and_then(|n| n.checked_add(key.len()))
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(GroupError::Invalid("provider state size overflow"))?;
            if next > MAX_PROVIDER_STATE_BYTES {
                return Err(GroupError::Invalid("provider state exceeds 16 MiB"));
            }
            out.extend_from_slice(&(key.len() as u64).to_be_bytes());
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    pub fn from_state(encoded: &[u8]) -> Result<Self> {
        if encoded.len() < 13
            || encoded.len() > MAX_PROVIDER_STATE_BYTES
            || !encoded.starts_with(PROVIDER_MAGIC)
        {
            return Err(GroupError::Invalid("provider state header is invalid"));
        }
        let mut at = PROVIDER_MAGIC.len();
        let count = usize::try_from(take_u64(encoded, &mut at)?)
            .map_err(|_| GroupError::Invalid("provider entry count overflows"))?;
        if count > MAX_PROVIDER_ENTRIES || count > encoded.len().saturating_sub(at) / 16 {
            return Err(GroupError::Invalid("provider state entry count is invalid"));
        }
        let mut values = HashMap::with_capacity(count);
        for _ in 0..count {
            let key_len = usize::try_from(take_u64(encoded, &mut at)?)
                .map_err(|_| GroupError::Invalid("provider key length overflows"))?;
            let value_len = usize::try_from(take_u64(encoded, &mut at)?)
                .map_err(|_| GroupError::Invalid("provider value length overflows"))?;
            if key_len > MAX_PROVIDER_KEY_BYTES || value_len > MAX_PROVIDER_STATE_BYTES {
                return Err(GroupError::Invalid("provider entry length is invalid"));
            }
            let end = at
                .checked_add(key_len)
                .and_then(|n| n.checked_add(value_len))
                .filter(|end| *end <= encoded.len())
                .ok_or(GroupError::Invalid("provider state is truncated"))?;
            let key_end = at + key_len;
            if values
                .insert(
                    encoded[at..key_end].to_vec(),
                    encoded[key_end..end].to_vec(),
                )
                .is_some()
            {
                return Err(GroupError::Invalid("provider state has duplicate key"));
            }
            at = end;
        }
        if at != encoded.len() {
            return Err(GroupError::Invalid("provider state has trailing bytes"));
        }
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(values),
            },
        })
    }
}

fn take_u64(bytes: &[u8], at: &mut usize) -> Result<u64> {
    let end = at
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or(GroupError::Invalid("provider state is truncated"))?;
    let value = u64::from_be_bytes(bytes[*at..end].try_into().expect("fixed length"));
    *at = end;
    Ok(value)
}

/// Locally generated MLS signing identity.  Its seed is deliberately separate
/// from all product keys and, like a KeyPackage, must be persisted per Copy.
pub struct Client {
    signer: SigningIdentity,
    evidence: Vec<u8>,
}

impl Client {
    pub fn generate(provider: &Provider, evidence: impl Into<Vec<u8>>) -> Result<Self> {
        let evidence = evidence.into();
        validate_evidence(&evidence)?;
        Ok(Self {
            signer: SigningIdentity::generate(provider)?,
            evidence,
        })
    }

    /// Restore a locally sealed client seed.  This exists for durable local
    /// installation; it is not a mechanism for copying another client's MLS
    /// state.
    pub fn from_seed(
        provider: &Provider,
        seed: [u8; 32],
        evidence: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let evidence = evidence.into();
        validate_evidence(&evidence)?;
        Ok(Self {
            signer: SigningIdentity::from_seed(provider, seed)?,
            evidence,
        })
    }

    pub fn member_id(&self) -> MemberId {
        MemberId::from_signing_key(&self.signer.to_public_vec())
            .expect("OpenMLS Ed25519 key has fixed width")
    }
    pub fn binding(&self) -> MemberBinding {
        MemberBinding::new(
            self.signer
                .to_public_vec()
                .try_into()
                .expect("OpenMLS Ed25519 key has fixed width"),
            self.evidence.clone(),
        )
        .expect("client evidence was validated")
    }
    pub fn export_sealed_state(&self) -> Vec<u8> {
        self.signer.sealed_seed().to_vec()
    }

    pub fn key_package(&self, provider: &Provider, profile: &GroupProfile) -> Result<Vec<u8>> {
        let package = KeyPackage::builder()
            .leaf_node_capabilities(group_capabilities())
            .leaf_node_extensions(profile_extensions(profile)?)
            .build(
                GROUP_CIPHERSUITE,
                provider,
                &self.signer,
                self.credential()?,
            )
            .map_err(mls)?;
        package.key_package().tls_serialize_detached().map_err(mls)
    }

    fn credential(&self) -> Result<CredentialWithKey> {
        Ok(CredentialWithKey {
            credential: BasicCredential::new(self.evidence.clone()).into(),
            signature_key: self.signer.to_public_vec().into(),
        })
    }
}

/// A loaded local MLS group.  It holds no product governance data; that is
/// intentionally supplied through ports at each operation.
pub struct Group {
    mls_group: MlsGroup,
    profile: GroupProfile,
}

#[derive(Clone, Debug)]
pub struct DetachedAdd {
    pub provider_state: Vec<u8>,
    pub group_id: Vec<u8>,
    pub prior_epoch: u64,
    pub next_epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
    pub authority: AuthorityGrant,
}

/// Exact detached Remove commit and its advanced private custody.
#[derive(Clone, Debug)]
pub struct DetachedRemove {
    pub provider_state: Vec<u8>,
    pub group_id: Vec<u8>,
    pub prior_epoch: u64,
    pub next_epoch: u64,
    pub commit: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
    pub authority: AuthorityGrant,
}

#[derive(Clone, Debug)]
pub struct DetachedJoin {
    pub provider_state: Vec<u8>,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub ratchet_tree: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DetachedCommit {
    pub provider_state: Vec<u8>,
    pub group_id: Vec<u8>,
    pub prior_epoch: u64,
    pub next_epoch: u64,
    pub ratchet_tree: Vec<u8>,
    pub authority: AuthorityGrant,
}

#[derive(Clone, Debug)]
pub struct DetachedApplication {
    pub provider_state: Vec<u8>,
    pub epoch: u64,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct OpenedApplication {
    pub provider_state: Vec<u8>,
    pub epoch: u64,
    pub sender: MemberId,
    pub plaintext: Vec<u8>,
}

impl Group {
    pub fn create(
        provider: &Provider,
        founder: &Client,
        group_id: &[u8],
        profile: GroupProfile,
        identity: &impl IdentityPort,
        now: u64,
    ) -> Result<Self> {
        valid_group_id(group_id)?;
        identity
            .verify_member(&profile, &founder.binding(), now)
            .map_err(GroupError::Identity)?
            .current_at(now)?;
        if MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .is_some()
        {
            return Err(GroupError::Invalid("group is already installed"));
        }
        let config = MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(GROUP_CIPHERSUITE)
            .capabilities(group_capabilities())
            .with_leaf_node_extensions(profile_extensions(&profile)?)
            .map_err(mls)?
            .with_group_context_extensions(group_extensions(&profile)?)
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group = MlsGroup::new_with_group_id(
            provider,
            &founder.signer,
            &config,
            GroupId::from_slice(group_id),
            founder.credential()?,
        )
        .map_err(mls)?;
        let group = Self { mls_group, profile };
        group.validate_profile(provider)?;
        Ok(group)
    }

    pub fn load(
        provider: &Provider,
        group_id: &[u8],
        expected_profile: &GroupProfile,
    ) -> Result<Self> {
        valid_group_id(group_id)?;
        let mls_group = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .ok_or(GroupError::Invalid("group state is absent"))?;
        let actual = context_profile(&mls_group)?;
        if &actual != expected_profile {
            return Err(GroupError::Invalid("authenticated group profile differs"));
        }
        let group = Self {
            mls_group,
            profile: actual,
        };
        group.validate_profile(provider)?;
        Ok(group)
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().as_slice().to_vec()
    }
    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }
    pub fn profile(&self) -> &GroupProfile {
        &self.profile
    }
    pub fn ratchet_tree(&self) -> Result<Vec<u8>> {
        self.mls_group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls)
    }
    pub fn facts(&self) -> Result<GroupFacts> {
        Ok(GroupFacts {
            group_id: self.group_id(),
            profile: self.profile.clone(),
            epoch: self.epoch(),
            members: self.members()?,
        })
    }

    pub fn members(&self) -> Result<Vec<MemberBinding>> {
        self.mls_group.members().map(binding_from_member).collect()
    }

    /// Build one exact Add/Welcome/tree transition on a copied provider.  The
    /// caller persists `provider_state` before publication; the original group
    /// and provider are untouched.
    pub fn stage_add(
        &self,
        provider: &Provider,
        actor: &Client,
        key_package_bytes: &[u8],
        identity: &impl IdentityPort,
        governance: &impl GovernancePort,
        now: u64,
    ) -> Result<DetachedAdd> {
        self.require_actor(actor)?;
        let prior_authority = self.member_authority(identity, now)?;
        let raw = Provider::from_state(&provider.export_state()?)?;
        let mut candidate = Self::load(&raw, &self.group_id(), &self.profile)?;
        if candidate.epoch() != self.epoch()
            || candidate.mls_group.pending_commit().is_some()
            || candidate.mls_group.pending_proposals().next().is_some()
        {
            return Err(GroupError::Invalid("Add requires a clean current group"));
        }
        let package = parse_key_package(&raw, key_package_bytes, &candidate.profile)?;
        let target = binding_from_leaf(package.leaf_node(), &candidate.profile)?;
        if candidate
            .members()?
            .iter()
            .any(|member| member.member_id == target.member_id)
        {
            return Err(GroupError::Invalid("MLS signing key is already a member"));
        }
        let first = governance
            .authorize(
                GovernanceAction::Add,
                &candidate.facts()?,
                actor.member_id(),
                Some(target.member_id),
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        let target_authority = identity
            .verify_member(&candidate.profile, &target, now)
            .map_err(GroupError::Identity)?
            .current_at(now)?;
        let prior_epoch = candidate.epoch();
        let (commit, welcome, _) = candidate
            .mls_group
            .add_members(&raw, &actor.signer, &[package])
            .map_err(mls)?;
        let commit = commit.to_bytes().map_err(mls)?;
        let welcome = welcome.to_bytes().map_err(mls)?;
        candidate
            .mls_group
            .merge_pending_commit(&raw)
            .map_err(mls)?;
        candidate.validate_profile(&raw)?;
        let resulting_authority = candidate.member_authority(identity, now)?;
        require_authority_unchanged(&prior_authority, &resulting_authority)?;
        let resulting_target = authority_for(&resulting_authority, target.member_id)?;
        if resulting_target.revision != target_authority.revision {
            return Err(GroupError::Identity(
                "target authority revision changed during Add".into(),
            ));
        }
        let final_grant = governance
            .authorize(
                GovernanceAction::Add,
                &candidate.facts()?,
                actor.member_id(),
                Some(target.member_id),
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        if final_grant.revision != first.revision {
            return Err(GroupError::Governance(
                "authority revision changed during Add".into(),
            ));
        }
        let ratchet_tree = candidate.ratchet_tree()?;
        Ok(DetachedAdd {
            provider_state: raw.export_state()?,
            group_id: candidate.group_id(),
            prior_epoch,
            next_epoch: candidate.epoch(),
            commit,
            welcome,
            ratchet_tree,
            authority: final_grant,
        })
    }

    /// Remove one current member on detached custody. The actor must own this
    /// local leaf; products supply authorization and persist before publication.
    pub fn stage_remove(
        &self,
        provider: &Provider,
        actor: &Client,
        target: MemberId,
        identity: &impl IdentityPort,
        governance: &impl GovernancePort,
        now: u64,
    ) -> Result<DetachedRemove> {
        self.require_actor(actor)?;
        if target == actor.member_id() {
            return Err(GroupError::Invalid("Remove cannot target the local actor"));
        }
        let raw = provider.detached()?;
        let mut candidate = Self::load(&raw, &self.group_id(), &self.profile)?;
        if candidate.epoch() != self.epoch()
            || candidate.mls_group.pending_commit().is_some()
            || candidate.mls_group.pending_proposals().next().is_some()
        {
            return Err(GroupError::Invalid("Remove requires a clean current group"));
        }
        let prior_authority = candidate.member_authority(identity, now)?;
        let leaf = candidate
            .mls_group
            .members()
            .find(|member| MemberId::from_signing_key(&member.signature_key).ok() == Some(target))
            .ok_or(GroupError::Invalid(
                "Remove target is not a current MLS member",
            ))?
            .index;
        let first = governance
            .authorize(
                GovernanceAction::Remove,
                &candidate.facts()?,
                actor.member_id(),
                Some(target),
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        let prior_epoch = candidate.epoch();
        let (commit, _, _) = candidate
            .mls_group
            .remove_members(&raw, &actor.signer, &[leaf])
            .map_err(mls)?;
        let commit = commit.to_bytes().map_err(mls)?;
        candidate
            .mls_group
            .merge_pending_commit(&raw)
            .map_err(mls)?;
        candidate.validate_profile(&raw)?;
        let survivors: Vec<_> = prior_authority
            .into_iter()
            .filter(|(member, _)| *member != target)
            .collect();
        require_authority_unchanged(&survivors, &candidate.member_authority(identity, now)?)?;
        let final_grant = governance
            .authorize(
                GovernanceAction::Remove,
                &candidate.facts()?,
                actor.member_id(),
                Some(target),
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        if first.revision != final_grant.revision {
            return Err(GroupError::Governance(
                "authority revision changed during Remove".into(),
            ));
        }
        Ok(DetachedRemove {
            provider_state: raw.export_state()?,
            group_id: candidate.group_id(),
            prior_epoch,
            next_epoch: candidate.epoch(),
            commit,
            ratchet_tree: candidate.ratchet_tree()?,
            authority: final_grant,
        })
    }

    /// Consume a Welcome only on copied local state.  The recipient's
    /// KeyPackage private material must already be in that provider snapshot.
    pub fn stage_join(
        provider: &Provider,
        client: &Client,
        expected_group_id: &[u8],
        expected_profile: &GroupProfile,
        welcome_bytes: &[u8],
        ratchet_tree_bytes: &[u8],
        identity: &impl IdentityPort,
        now: u64,
    ) -> Result<DetachedJoin> {
        valid_group_id(expected_group_id)?;
        let raw = Provider::from_state(&provider.export_state()?)?;
        if MlsGroup::load(raw.storage(), &GroupId::from_slice(expected_group_id))
            .map_err(mls)?
            .is_some()
        {
            return Err(GroupError::Invalid(
                "Welcome cannot replace an installed group",
            ));
        }
        let welcome = match MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(mls)?
            .extract()
        {
            MlsMessageBodyIn::Welcome(value) => value,
            _ => return Err(GroupError::Invalid("expected MLS Welcome")),
        };
        let staged =
            StagedWelcome::new_from_welcome(&raw, &join_config(), welcome, None).map_err(mls)?;
        if staged.group_context().group_id().as_slice() != expected_group_id {
            return Err(GroupError::Invalid("Welcome group ID differs"));
        }
        let joined = staged.into_group(&raw).map_err(mls)?;
        let group = Self {
            mls_group: joined,
            profile: context_profile_from_group_id(&raw, expected_group_id, expected_profile)?,
        };
        group.validate_profile(&raw)?;
        if group.ratchet_tree()? != ratchet_tree_bytes {
            return Err(GroupError::Invalid(
                "Welcome ratchet tree differs from supplied tree",
            ));
        }
        let own = group
            .mls_group
            .own_leaf_node()
            .ok_or(GroupError::Invalid("joined MLS leaf is absent"))?;
        if binding_from_leaf(own, &group.profile)? != client.binding() {
            return Err(GroupError::Invalid(
                "Welcome recipient leaf differs from local client",
            ));
        }
        let first_authority = group.member_authority(identity, now)?;
        let final_authority = group.member_authority(identity, now)?;
        require_authority_unchanged(&first_authority, &final_authority)?;
        Ok(DetachedJoin {
            provider_state: raw.export_state()?,
            group_id: group.group_id(),
            epoch: group.epoch(),
            ratchet_tree: group.ratchet_tree()?,
        })
    }

    /// Validate, authorize, and merge one received MLS Commit on copied state.
    /// The caller may only install the detached state after its own durable CAS.
    pub fn stage_apply_commit(
        &self,
        provider: &Provider,
        commit_bytes: &[u8],
        identity: &impl IdentityPort,
        governance: &impl GovernancePort,
        now: u64,
    ) -> Result<DetachedCommit> {
        let raw = Provider::from_state(&provider.export_state()?)?;
        let mut candidate = Self::load(&raw, &self.group_id(), &self.profile)?;
        let prior_authority = candidate.member_authority(identity, now)?;
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(mls)?
            .try_into_protocol_message()
            .map_err(mls)?;
        let processed = candidate
            .mls_group
            .process_message(&raw, message)
            .map_err(mls)?;
        let sender = sender_member_id(&candidate, processed.sender())?;
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(value) => value,
            _ => return Err(GroupError::Invalid("expected MLS Commit")),
        };
        if profile_from_context(staged.group_context().extensions())? != candidate.profile {
            return Err(GroupError::Invalid(
                "Commit changes authenticated product profile",
            ));
        }
        let mut added_authority = Vec::new();
        for add in staged.add_proposals() {
            let binding = binding_from_leaf(
                add.add_proposal().key_package().leaf_node(),
                &candidate.profile,
            )?;
            let authority = identity
                .verify_member(&candidate.profile, &binding, now)
                .map_err(GroupError::Identity)?
                .current_at(now)?;
            added_authority.push((binding.member_id, authority));
        }
        let prior_epoch = candidate.epoch();
        let first = governance
            .authorize(
                GovernanceAction::ApplyCommit,
                &candidate.facts()?,
                sender,
                None,
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        candidate
            .mls_group
            .merge_staged_commit(&raw, *staged)
            .map_err(mls)?;
        candidate.validate_profile(&raw)?;
        let resulting_authority = candidate.member_authority(identity, now)?;
        // Authenticated removals intentionally disappear. Fence authority only
        // for prior members that remain in the resulting MLS roster.
        let survivors: Vec<_> = prior_authority
            .into_iter()
            .filter(|(member, _)| {
                resulting_authority
                    .iter()
                    .any(|(current, _)| current == member)
            })
            .collect();
        require_authority_unchanged(&survivors, &resulting_authority)?;
        require_authority_unchanged(&added_authority, &resulting_authority)?;
        let final_grant = governance
            .authorize(
                GovernanceAction::ApplyCommit,
                &candidate.facts()?,
                sender,
                None,
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        if first.revision != final_grant.revision {
            return Err(GroupError::Governance(
                "authority revision changed during Commit".into(),
            ));
        }
        Ok(DetachedCommit {
            provider_state: raw.export_state()?,
            group_id: candidate.group_id(),
            prior_epoch,
            next_epoch: candidate.epoch(),
            ratchet_tree: candidate.ratchet_tree()?,
            authority: final_grant,
        })
    }

    /// Seal application bytes through MLS on detached state.  Product payload
    /// schemas remain outside Group; only their authenticated ciphertext is MLS.
    pub fn stage_seal_application(
        &self,
        provider: &Provider,
        actor: &Client,
        plaintext: &[u8],
        governance: &impl GovernancePort,
        now: u64,
    ) -> Result<DetachedApplication> {
        if plaintext.len() > MAX_APPLICATION_BYTES {
            return Err(GroupError::Invalid("application payload exceeds 1 MiB"));
        }
        self.require_actor(actor)?;
        let raw = Provider::from_state(&provider.export_state()?)?;
        let mut candidate = Self::load(&raw, &self.group_id(), &self.profile)?;
        governance
            .authorize(
                GovernanceAction::SealApplication,
                &candidate.facts()?,
                actor.member_id(),
                None,
                now,
            )
            .map_err(GroupError::Governance)?
            .current_at(now)?;
        let message = candidate
            .mls_group
            .create_message(&raw, &actor.signer, plaintext)
            .map_err(mls)?
            .to_bytes()
            .map_err(mls)?;
        Ok(DetachedApplication {
            provider_state: raw.export_state()?,
            epoch: candidate.epoch(),
            message,
        })
    }

    pub fn stage_open_application(
        &self,
        provider: &Provider,
        message_bytes: &[u8],
    ) -> Result<OpenedApplication> {
        let raw = Provider::from_state(&provider.export_state()?)?;
        let mut candidate = Self::load(&raw, &self.group_id(), &self.profile)?;
        let message = MlsMessageIn::tls_deserialize_exact(message_bytes)
            .map_err(mls)?
            .try_into_protocol_message()
            .map_err(mls)?;
        let processed = candidate
            .mls_group
            .process_message(&raw, message)
            .map_err(mls)?;
        let sender = sender_member_id(&candidate, processed.sender())?;
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(value) => value.into_bytes(),
            _ => return Err(GroupError::Invalid("expected MLS application message")),
        };
        Ok(OpenedApplication {
            provider_state: raw.export_state()?,
            epoch: candidate.epoch(),
            sender,
            plaintext,
        })
    }

    fn validate_profile(&self, provider: &Provider) -> Result<()> {
        if context_profile(&self.mls_group)? != self.profile {
            return Err(GroupError::Invalid("group profile pin differs"));
        }
        let public =
            openmls::group::PublicGroup::load(provider.storage(), self.mls_group.group_id())
                .map_err(mls)?
                .ok_or(GroupError::Invalid("public group state is absent"))?;
        for member in self.mls_group.members() {
            let leaf = public
                .leaf(member.index)
                .ok_or(GroupError::Invalid("public member leaf is absent"))?;
            let _ = binding_from_leaf(leaf, &self.profile)?;
        }
        Ok(())
    }

    fn member_authority(
        &self,
        identity: &impl IdentityPort,
        now: u64,
    ) -> Result<Vec<(MemberId, AuthorityGrant)>> {
        let mut authority = self
            .members()?
            .into_iter()
            .map(|member| {
                let grant = identity
                    .verify_member(&self.profile, &member, now)
                    .map_err(GroupError::Identity)?
                    .current_at(now)?;
                Ok((member.member_id, grant))
            })
            .collect::<Result<Vec<_>>>()?;
        authority.sort_by_key(|(member, _)| *member);
        Ok(authority)
    }

    fn require_actor(&self, actor: &Client) -> Result<()> {
        if self
            .mls_group
            .own_leaf_node()
            .is_none_or(|leaf| leaf.signature_key().as_slice() != actor.signer.public())
        {
            return Err(GroupError::Invalid(
                "local actor signing key differs from local MLS leaf",
            ));
        }
        if !self
            .members()?
            .iter()
            .any(|member| member == &actor.binding())
        {
            return Err(GroupError::Invalid(
                "local actor is not a current MLS member",
            ));
        }
        Ok(())
    }
}

/// Every member that was already trusted for a transition must still have the
/// same product authority revision when the detached state is returned.  A
/// later expiry is fine; a changed revision means the product must restage.
fn require_authority_unchanged(
    before: &[(MemberId, AuthorityGrant)],
    after: &[(MemberId, AuthorityGrant)],
) -> Result<()> {
    for (member, expected) in before {
        let actual = authority_for(after, *member)?;
        if actual.revision != expected.revision {
            return Err(GroupError::Identity(
                "member authority revision changed during MLS transition".into(),
            ));
        }
    }
    Ok(())
}

fn authority_for(
    authority: &[(MemberId, AuthorityGrant)],
    member: MemberId,
) -> Result<AuthorityGrant> {
    authority
        .iter()
        .find_map(|(candidate, grant)| (*candidate == member).then_some(*grant))
        .ok_or(GroupError::Identity(
            "member authority is absent after MLS transition".into(),
        ))
}

fn valid_group_id(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.len() > 255 {
        return Err(GroupError::Invalid("MLS group ID must be 1..=255 bytes"));
    }
    Ok(())
}

fn group_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[GROUP_CIPHERSUITE]),
        Some(&[ExtensionType::AppDataDictionary]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

fn profile_extensions(profile: &GroupProfile) -> Result<Extensions<LeafNode>> {
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(PROFILE_COMPONENT, profile.as_bytes().to_vec());
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .map_err(mls)
}

fn group_extensions(profile: &GroupProfile) -> Result<Extensions<GroupContext>> {
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(PROFILE_COMPONENT, profile.as_bytes().to_vec());
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
    ])
    .map_err(|_| GroupError::Invalid("group profile extensions are invalid"))
}

fn context_profile(group: &MlsGroup) -> Result<GroupProfile> {
    profile_from_context(group.extensions())
}
fn profile_from_context(extensions: &Extensions<GroupContext>) -> Result<GroupProfile> {
    let dictionary = extensions
        .app_data_dictionary()
        .ok_or(GroupError::Invalid("group profile dictionary is absent"))?
        .dictionary();
    GroupProfile::new(
        dictionary
            .get(&PROFILE_COMPONENT)
            .ok_or(GroupError::Invalid("group profile is absent"))?
            .to_vec(),
    )
}
fn context_profile_from_group_id(
    provider: &Provider,
    group_id: &[u8],
    expected: &GroupProfile,
) -> Result<GroupProfile> {
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
        .map_err(mls)?
        .ok_or(GroupError::Invalid("joined group state is absent"))?;
    let profile = context_profile(&group)?;
    if &profile != expected {
        return Err(GroupError::Invalid(
            "Welcome profile differs from expected profile",
        ));
    }
    Ok(profile)
}
fn binding_from_leaf(leaf: &LeafNode, profile: &GroupProfile) -> Result<MemberBinding> {
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .ok_or(GroupError::Invalid(
            "member leaf profile dictionary is absent",
        ))?
        .dictionary();
    if dictionary.get(&PROFILE_COMPONENT) != Some(profile.as_bytes()) {
        return Err(GroupError::Invalid(
            "member leaf profile differs from group profile",
        ));
    }
    MemberBinding::new(
        leaf.signature_key()
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::Invalid("MLS signing key must be 32 bytes"))?,
        leaf.credential().serialized_content().to_vec(),
    )
}
fn binding_from_member(member: openmls::group::Member) -> Result<MemberBinding> {
    MemberBinding::new(
        member
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::Invalid("MLS signing key must be 32 bytes"))?,
        member.credential.serialized_content().to_vec(),
    )
}
fn parse_key_package(
    provider: &Provider,
    bytes: &[u8],
    profile: &GroupProfile,
) -> Result<KeyPackage> {
    let package = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(mls)?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls)?;
    if package.ciphersuite() != GROUP_CIPHERSUITE {
        return Err(GroupError::Invalid(
            "KeyPackage ciphersuite differs from group profile",
        ));
    }
    let _ = binding_from_leaf(package.leaf_node(), profile)?;
    Ok(package)
}
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}
fn sender_member_id(group: &Group, sender: &Sender) -> Result<MemberId> {
    let Sender::Member(index) = sender else {
        return Err(GroupError::Invalid("external MLS sender is not permitted"));
    };
    let member = group
        .mls_group
        .members()
        .find(|member| member.index == *index)
        .ok_or(GroupError::Invalid("MLS sender leaf is absent"))?;
    MemberId::from_signing_key(member.signature_key.as_slice())
}

/// Browser bindings expose real MLS transitions, but no product verifier or
/// policy implementation.  Callers validate product evidence before passing
/// it to this ABI and pass the resulting bounded authority facts for every
/// transition.  The bytes remain opaque to Group.
#[cfg(feature = "wasm")]
mod native {
    use super::*;
    use js_sys::{Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

    const SNAPSHOT_MAGIC: &[u8; 5] = b"GFN01";

    fn js_error(error: GroupError) -> JsError {
        JsError::new(&error.to_string())
    }

    /// Validated product authority facts.  Revisions and expiry are supplied
    /// by the product; Group only fences them across MLS transitions.
    #[wasm_bindgen]
    pub struct NativeAuthorityFacts {
        identity_revision: u64,
        identity_valid_until: u64,
        governance_revision: u64,
        governance_valid_until: u64,
    }

    #[wasm_bindgen]
    impl NativeAuthorityFacts {
        #[wasm_bindgen(constructor)]
        pub fn new(
            identity_revision: u64,
            identity_valid_until: u64,
            governance_revision: u64,
            governance_valid_until: u64,
        ) -> Self {
            Self {
                identity_revision,
                identity_valid_until,
                governance_revision,
                governance_valid_until,
            }
        }
    }

    struct ValidatedIdentity {
        facts: AuthorityGrant,
    }
    impl IdentityPort for ValidatedIdentity {
        fn verify_member(
            &self,
            _profile: &GroupProfile,
            _binding: &MemberBinding,
            _now: u64,
        ) -> std::result::Result<AuthorityGrant, String> {
            Ok(self.facts)
        }
    }

    struct ValidatedGovernance {
        facts: AuthorityGrant,
    }
    impl GovernancePort for ValidatedGovernance {
        fn authorize(
            &self,
            _action: GovernanceAction,
            _facts: &GroupFacts,
            _actor: MemberId,
            _target: Option<MemberId>,
            _now: u64,
        ) -> std::result::Result<AuthorityGrant, String> {
            Ok(self.facts)
        }
    }

    impl NativeAuthorityFacts {
        fn identity(&self) -> ValidatedIdentity {
            ValidatedIdentity {
                facts: AuthorityGrant {
                    revision: self.identity_revision,
                    valid_until: self.identity_valid_until,
                },
            }
        }
        fn governance(&self) -> ValidatedGovernance {
            ValidatedGovernance {
                facts: AuthorityGrant {
                    revision: self.governance_revision,
                    valid_until: self.governance_valid_until,
                },
            }
        }
    }

    #[wasm_bindgen(typescript_custom_section)]
    const NATIVE_GROUP_RESULT_TYPES: &str = r#"
export interface NativeGroupResult { snapshot: Uint8Array; groupId: Uint8Array; profile: Uint8Array; epoch: string; }
export interface NativeGroupKeyPackageResult { snapshot: Uint8Array; keyPackage: Uint8Array; memberId: Uint8Array; }
export interface NativeGroupAddResult extends NativeGroupResult { priorEpoch: string; commit: Uint8Array; welcome: Uint8Array; ratchetTree: Uint8Array; }
export interface NativeGroupCommitResult extends NativeGroupResult { priorEpoch: string; ratchetTree: Uint8Array; }
export interface NativeGroupRemoveResult extends NativeGroupCommitResult { commit: Uint8Array; }
export interface NativeGroupSealResult extends NativeGroupResult { message: Uint8Array; }
export interface NativeGroupOpenResult extends NativeGroupResult { sender: Uint8Array; plaintext: Uint8Array; }
export interface NativeMemberProofResult { signingKey: Uint8Array; signature: Uint8Array; }
"#;

    /// One independent local MLS client and its in-memory provider.  It never
    /// opens a database. `export_snapshot` is the only persistence boundary.
    #[wasm_bindgen]
    pub struct NativeClient {
        provider: Provider,
        client: Client,
    }

    #[wasm_bindgen]
    impl NativeClient {
        #[wasm_bindgen(constructor)]
        pub fn new(evidence: Vec<u8>) -> std::result::Result<Self, JsError> {
            let provider = Provider::new();
            let client = Client::generate(&provider, evidence).map_err(js_error)?;
            Ok(Self { provider, client })
        }

        /// Restores only a snapshot previously emitted by this ABI.  The
        /// caller is responsible for authenticating and atomically storing it.
        #[wasm_bindgen(js_name = fromSnapshot)]
        pub fn from_snapshot(snapshot: Vec<u8>) -> std::result::Result<Self, JsError> {
            let (provider_state, seed, evidence) = decode_snapshot(&snapshot).map_err(js_error)?;
            let provider = Provider::from_state(&provider_state).map_err(js_error)?;
            let client = Client::from_seed(&provider, seed, evidence).map_err(js_error)?;
            Ok(Self { provider, client })
        }

        #[wasm_bindgen(js_name = exportSnapshot)]
        pub fn export_snapshot(&self) -> std::result::Result<Vec<u8>, JsError> {
            snapshot_for(&self.provider, &self.client).map_err(js_error)
        }

        #[wasm_bindgen(js_name = memberId)]
        pub fn member_id(&self) -> Vec<u8> {
            self.client.member_id().as_bytes().to_vec()
        }

        /// Signs a Group-domain transcript with this Copy's existing MLS key.
        /// This does not expose the key or change the MLS ratchet.
        #[wasm_bindgen(js_name = signMemberProof, unchecked_return_type = "NativeMemberProofResult")]
        pub fn sign_member_proof(
            &self,
            transcript: Vec<u8>,
        ) -> std::result::Result<JsValue, JsError> {
            use openmls_traits::signatures::Signer;
            if transcript.is_empty() || transcript.len() > 512 * 1024 {
                return Err(JsError::new("member proof transcript exceeds bounds"));
            }
            let value: serde_json::Value = serde_json::from_slice(&transcript).map_err(|_| {
                JsError::new("member proof requires a Foundation-domain transcript")
            })?;
            let domain = value.get("domain").and_then(serde_json::Value::as_str);
            if !domain.is_some_and(|domain| {
                domain.starts_with("group-foundation.group.")
                    || domain.starts_with("group-foundation.admission.")
            }) {
                return Err(JsError::new(
                    "member proof requires a Foundation-domain transcript",
                ));
            }
            let signature = self
                .client
                .signer
                .sign(&transcript)
                .map_err(|_| JsError::new("member proof signing failed"))?;
            let result = Object::new().into();
            set_bytes(&result, "signingKey", &self.client.signer.to_public_vec())?;
            set_bytes(&result, "signature", &signature)?;
            Ok(result)
        }

        #[wasm_bindgen(js_name = createGroup, unchecked_return_type = "NativeGroupResult")]
        pub fn create_group(
            &mut self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            authority: &NativeAuthorityFacts,
            now: u64,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let group = Group::create(
                &self.provider,
                &self.client,
                &group_id,
                profile,
                &authority.identity(),
                now,
            )
            .map_err(js_error)?;
            group_result(
                snapshot_for(&self.provider, &self.client).map_err(js_error)?,
                &group.group_id(),
                group.profile().as_bytes(),
                group.epoch(),
            )
        }

        #[wasm_bindgen(js_name = createKeyPackage, unchecked_return_type = "NativeGroupKeyPackageResult")]
        pub fn create_key_package(
            &mut self,
            profile: Vec<u8>,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let package = self
                .client
                .key_package(&self.provider, &profile)
                .map_err(js_error)?;
            let result = Object::new().into();
            set_bytes(
                &result,
                "snapshot",
                &snapshot_for(&self.provider, &self.client).map_err(js_error)?,
            )?;
            set_bytes(&result, "keyPackage", &package)?;
            set_bytes(&result, "memberId", self.client.member_id().as_bytes())?;
            Ok(result)
        }

        /// Builds an Add on a copied provider. The returned snapshot is the
        /// only advanced founder state; this client remains unchanged.
        #[wasm_bindgen(js_name = stageAdd, unchecked_return_type = "NativeGroupAddResult")]
        pub fn stage_add(
            &self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            key_package: Vec<u8>,
            authority: &NativeAuthorityFacts,
            now: u64,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let group = Group::load(&self.provider, &group_id, &profile).map_err(js_error)?;
            let output = group
                .stage_add(
                    &self.provider,
                    &self.client,
                    &key_package,
                    &authority.identity(),
                    &authority.governance(),
                    now,
                )
                .map_err(js_error)?;
            let result = group_result(
                snapshot_from_parts(&output.provider_state, &self.client).map_err(js_error)?,
                &output.group_id,
                profile.as_bytes(),
                output.next_epoch,
            )?;
            set_string(&result, "priorEpoch", output.prior_epoch)?;
            set_bytes(&result, "commit", &output.commit)?;
            set_bytes(&result, "welcome", &output.welcome)?;
            set_bytes(&result, "ratchetTree", &output.ratchet_tree)?;
            Ok(result)
        }

        #[wasm_bindgen(js_name = stageRemove, unchecked_return_type = "NativeGroupRemoveResult")]
        pub fn stage_remove(
            &self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            target: Vec<u8>,
            authority: &NativeAuthorityFacts,
            now: u64,
        ) -> std::result::Result<JsValue, JsError> {
            let target = MemberId(
                target
                    .try_into()
                    .map_err(|_| JsError::new("Remove target must be a 32 byte member ID"))?,
            );
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let group = Group::load(&self.provider, &group_id, &profile).map_err(js_error)?;
            let output = group
                .stage_remove(
                    &self.provider,
                    &self.client,
                    target,
                    &authority.identity(),
                    &authority.governance(),
                    now,
                )
                .map_err(js_error)?;
            let result = group_result(
                snapshot_from_parts(&output.provider_state, &self.client).map_err(js_error)?,
                &output.group_id,
                profile.as_bytes(),
                output.next_epoch,
            )?;
            set_string(&result, "priorEpoch", output.prior_epoch)?;
            set_bytes(&result, "commit", &output.commit)?;
            set_bytes(&result, "ratchetTree", &output.ratchet_tree)?;
            Ok(result)
        }

        #[wasm_bindgen(js_name = stageJoin, unchecked_return_type = "NativeGroupResult")]
        pub fn stage_join(
            &self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            welcome: Vec<u8>,
            ratchet_tree: Vec<u8>,
            authority: &NativeAuthorityFacts,
            now: u64,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let output = Group::stage_join(
                &self.provider,
                &self.client,
                &group_id,
                &profile,
                &welcome,
                &ratchet_tree,
                &authority.identity(),
                now,
            )
            .map_err(js_error)?;
            group_result(
                snapshot_from_parts(&output.provider_state, &self.client).map_err(js_error)?,
                &output.group_id,
                profile.as_bytes(),
                output.epoch,
            )
        }

        #[wasm_bindgen(js_name = stageApplyCommit, unchecked_return_type = "NativeGroupCommitResult")]
        pub fn stage_apply_commit(
            &self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            commit: Vec<u8>,
            authority: &NativeAuthorityFacts,
            now: u64,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let group = Group::load(&self.provider, &group_id, &profile).map_err(js_error)?;
            let output = group
                .stage_apply_commit(
                    &self.provider,
                    &commit,
                    &authority.identity(),
                    &authority.governance(),
                    now,
                )
                .map_err(js_error)?;
            let result = group_result(
                snapshot_from_parts(&output.provider_state, &self.client).map_err(js_error)?,
                &output.group_id,
                profile.as_bytes(),
                output.next_epoch,
            )?;
            set_string(&result, "priorEpoch", output.prior_epoch)?;
            set_bytes(&result, "ratchetTree", &output.ratchet_tree)?;
            Ok(result)
        }

        #[wasm_bindgen(js_name = stageSealApplication, unchecked_return_type = "NativeGroupSealResult")]
        pub fn stage_seal_application(
            &self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            plaintext: Vec<u8>,
            authority: &NativeAuthorityFacts,
            now: u64,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let group = Group::load(&self.provider, &group_id, &profile).map_err(js_error)?;
            let output = group
                .stage_seal_application(
                    &self.provider,
                    &self.client,
                    &plaintext,
                    &authority.governance(),
                    now,
                )
                .map_err(js_error)?;
            let result = group_result(
                snapshot_from_parts(&output.provider_state, &self.client).map_err(js_error)?,
                &group_id,
                profile.as_bytes(),
                output.epoch,
            )?;
            set_bytes(&result, "message", &output.message)?;
            Ok(result)
        }

        #[wasm_bindgen(js_name = stageOpenApplication, unchecked_return_type = "NativeGroupOpenResult")]
        pub fn stage_open_application(
            &self,
            group_id: Vec<u8>,
            profile: Vec<u8>,
            message: Vec<u8>,
        ) -> std::result::Result<JsValue, JsError> {
            let profile = GroupProfile::new(profile).map_err(js_error)?;
            let group = Group::load(&self.provider, &group_id, &profile).map_err(js_error)?;
            let output = group
                .stage_open_application(&self.provider, &message)
                .map_err(js_error)?;
            let result = group_result(
                snapshot_from_parts(&output.provider_state, &self.client).map_err(js_error)?,
                &group_id,
                profile.as_bytes(),
                output.epoch,
            )?;
            set_bytes(&result, "sender", output.sender.as_bytes())?;
            set_bytes(&result, "plaintext", &output.plaintext)?;
            Ok(result)
        }
    }

    fn snapshot_for(provider: &Provider, client: &Client) -> Result<Vec<u8>> {
        snapshot_from_parts(&provider.export_state()?, client)
    }

    fn snapshot_from_parts(provider_state: &[u8], client: &Client) -> Result<Vec<u8>> {
        if provider_state.len() > MAX_PROVIDER_STATE_BYTES {
            return Err(GroupError::Invalid("provider state exceeds 16 MiB"));
        }
        let seed = client.export_sealed_state();
        let evidence = &client.evidence;
        let total = SNAPSHOT_MAGIC
            .len()
            .checked_add(12)
            .and_then(|value| value.checked_add(provider_state.len()))
            .and_then(|value| value.checked_add(seed.len()))
            .and_then(|value| value.checked_add(evidence.len()))
            .ok_or(GroupError::Invalid("native snapshot size overflow"))?;
        if total > MAX_PROVIDER_STATE_BYTES + MAX_EVIDENCE_BYTES + 64 {
            return Err(GroupError::Invalid("native snapshot exceeds size limit"));
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        for value in [provider_state.len(), seed.len(), evidence.len()] {
            let value = u32::try_from(value)
                .map_err(|_| GroupError::Invalid("native snapshot component is too large"))?;
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(provider_state);
        out.extend_from_slice(&seed);
        out.extend_from_slice(evidence);
        Ok(out)
    }

    fn decode_snapshot(encoded: &[u8]) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
        if encoded.len() < SNAPSHOT_MAGIC.len() + 12 || !encoded.starts_with(SNAPSHOT_MAGIC) {
            return Err(GroupError::Invalid("native snapshot header is invalid"));
        }
        let mut at = SNAPSHOT_MAGIC.len();
        let provider_len = take_u32(encoded, &mut at)? as usize;
        let seed_len = take_u32(encoded, &mut at)? as usize;
        let evidence_len = take_u32(encoded, &mut at)? as usize;
        if provider_len > MAX_PROVIDER_STATE_BYTES
            || seed_len != 32
            || evidence_len > MAX_EVIDENCE_BYTES
        {
            return Err(GroupError::Invalid(
                "native snapshot component length is invalid",
            ));
        }
        let end = at
            .checked_add(provider_len)
            .and_then(|value| value.checked_add(seed_len))
            .and_then(|value| value.checked_add(evidence_len))
            .filter(|end| *end == encoded.len())
            .ok_or(GroupError::Invalid(
                "native snapshot is truncated or has trailing bytes",
            ))?;
        let provider_end = at + provider_len;
        let seed_end = provider_end + seed_len;
        let seed: [u8; 32] = encoded[provider_end..seed_end]
            .try_into()
            .expect("native snapshot seed length was checked");
        let evidence = encoded[seed_end..end].to_vec();
        validate_evidence(&evidence)?;
        Ok((encoded[at..provider_end].to_vec(), seed, evidence))
    }

    fn take_u32(bytes: &[u8], at: &mut usize) -> Result<u32> {
        let end = at
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or(GroupError::Invalid("native snapshot is truncated"))?;
        let value = u32::from_be_bytes(bytes[*at..end].try_into().expect("fixed length"));
        *at = end;
        Ok(value)
    }

    fn set(result: &JsValue, name: &str, value: &JsValue) -> std::result::Result<(), JsError> {
        Reflect::set(result, &JsValue::from_str(name), value)
            .map(|_| ())
            .map_err(|_| JsError::new("could not construct native result"))
    }
    fn set_bytes(result: &JsValue, name: &str, value: &[u8]) -> std::result::Result<(), JsError> {
        set(result, name, &Uint8Array::from(value).into())
    }
    fn set_string(result: &JsValue, name: &str, value: u64) -> std::result::Result<(), JsError> {
        // Epochs are decimal strings so the ABI works in browsers without a
        // BigInt policy and never loses 64-bit precision.
        set(result, name, &JsValue::from_str(&value.to_string()))
    }
    fn group_result(
        snapshot: Vec<u8>,
        group_id: &[u8],
        profile: &[u8],
        epoch: u64,
    ) -> std::result::Result<JsValue, JsError> {
        let result = Object::new().into();
        set_bytes(&result, "snapshot", &snapshot)?;
        set_bytes(&result, "groupId", group_id)?;
        set_bytes(&result, "profile", profile)?;
        set_string(&result, "epoch", epoch)?;
        Ok(result)
    }

    #[wasm_bindgen]
    pub fn member_fingerprint(signing_key: &[u8]) -> std::result::Result<Vec<u8>, JsError> {
        Ok(MemberId::from_signing_key(signing_key)
            .map_err(js_error)?
            .0
            .to_vec())
    }
}

#[cfg(feature = "wasm")]
pub use native::{NativeAuthorityFacts, NativeClient, member_fingerprint};

#[cfg(test)]
mod tests {
    use super::*;

    struct Identity;
    impl IdentityPort for Identity {
        fn verify_member(
            &self,
            _profile: &GroupProfile,
            binding: &MemberBinding,
            now: u64,
        ) -> std::result::Result<AuthorityGrant, String> {
            if binding.evidence.starts_with(b"trusted:") {
                Ok(AuthorityGrant {
                    revision: 7,
                    valid_until: now + 60,
                })
            } else {
                Err("untrusted evidence".into())
            }
        }
    }
    struct Governance;
    impl GovernancePort for Governance {
        fn authorize(
            &self,
            _action: GovernanceAction,
            _facts: &GroupFacts,
            _actor: MemberId,
            _target: Option<MemberId>,
            now: u64,
        ) -> std::result::Result<AuthorityGrant, String> {
            Ok(AuthorityGrant {
                revision: 9,
                valid_until: now + 60,
            })
        }
    }

    #[test]
    fn detached_add_join_and_application_use_independent_mls_state() {
        let profile = GroupProfile::new(b"hyperkey/group-profile/v1".to_vec()).unwrap();
        let founder_provider = Provider::new();
        let founder = Client::generate(&founder_provider, b"trusted:founder".to_vec()).unwrap();
        let founder_id = founder.member_id();
        let group_id = b"independent-copy-group-id-0000001";
        let founder_group = Group::create(
            &founder_provider,
            &founder,
            group_id,
            profile.clone(),
            &Identity,
            100,
        )
        .unwrap();

        let copy_provider = Provider::new();
        let copy = Client::generate(&copy_provider, b"trusted:copy".to_vec()).unwrap();
        assert_ne!(founder.member_id(), copy.member_id());
        let wrong_profile = GroupProfile::new(b"other-product-profile/v1".to_vec()).unwrap();
        let wrong_package = copy.key_package(&copy_provider, &wrong_profile).unwrap();
        assert!(
            founder_group
                .stage_add(
                    &founder_provider,
                    &founder,
                    &wrong_package,
                    &Identity,
                    &Governance,
                    100,
                )
                .is_err()
        );
        let package = copy.key_package(&copy_provider, &profile).unwrap();
        let add = founder_group
            .stage_add(
                &founder_provider,
                &founder,
                &package,
                &Identity,
                &Governance,
                100,
            )
            .unwrap();
        assert_eq!(add.prior_epoch + 1, add.next_epoch);
        assert!(!add.commit.is_empty() && !add.welcome.is_empty());

        let advanced_founder_provider = Provider::from_state(&add.provider_state).unwrap();
        let advanced_founder = Group::load(&advanced_founder_provider, group_id, &profile).unwrap();
        assert!(
            Group::stage_join(
                &copy_provider,
                &copy,
                b"wrong-group-id",
                &profile,
                &add.welcome,
                &add.ratchet_tree,
                &Identity,
                100,
            )
            .is_err()
        );
        let join = Group::stage_join(
            &copy_provider,
            &copy,
            group_id,
            &profile,
            &add.welcome,
            &add.ratchet_tree,
            &Identity,
            100,
        )
        .unwrap();
        let joined_copy_provider = Provider::from_state(&join.provider_state).unwrap();
        let joined_copy = Group::load(&joined_copy_provider, group_id, &profile).unwrap();
        assert_eq!(advanced_founder.members().unwrap().len(), 2);
        assert_eq!(joined_copy.members().unwrap().len(), 2);

        let sealed = advanced_founder
            .stage_seal_application(
                &advanced_founder_provider,
                &founder,
                b"opaque product payload",
                &Governance,
                101,
            )
            .unwrap();
        assert!(
            joined_copy
                .stage_open_application(&joined_copy_provider, b"not an MLS application message")
                .is_err()
        );
        let opened = joined_copy
            .stage_open_application(&joined_copy_provider, &sealed.message)
            .unwrap();
        assert_eq!(opened.sender, founder_id);
        assert_eq!(opened.plaintext, b"opaque product payload");
        assert_ne!(sealed.provider_state, add.provider_state);

        // Ratchets advance independently in each direction. A consumed frame
        // is rejected against the current durable recipient state, while a
        // second frame succeeds against that same advanced state.
        let after_send_provider = Provider::from_state(&sealed.provider_state).unwrap();
        let after_send = Group::load(&after_send_provider, group_id, &profile).unwrap();
        let after_receive_provider = Provider::from_state(&opened.provider_state).unwrap();
        let after_receive = Group::load(&after_receive_provider, group_id, &profile).unwrap();
        assert!(
            after_receive
                .stage_open_application(&after_receive_provider, &sealed.message)
                .is_err()
        );
        let second_frame = after_send
            .stage_seal_application(
                &after_send_provider,
                &founder,
                b"second payload",
                &Governance,
                102,
            )
            .unwrap();
        let second_open = after_receive
            .stage_open_application(&after_receive_provider, &second_frame.message)
            .unwrap();
        assert_eq!(second_open.plaintext, b"second payload");

        // A current Copy can independently authenticate and apply the exact
        // commit created by another Copy; no product account state is carried
        // in the native transition.
        let third_provider = Provider::new();
        let third = Client::generate(&third_provider, b"trusted:third".to_vec()).unwrap();
        let third_package = third.key_package(&third_provider, &profile).unwrap();
        let second_add = advanced_founder
            .stage_add(
                &advanced_founder_provider,
                &founder,
                &third_package,
                &Identity,
                &Governance,
                102,
            )
            .unwrap();
        let applied = joined_copy
            .stage_apply_commit(
                &joined_copy_provider,
                &second_add.commit,
                &Identity,
                &Governance,
                102,
            )
            .unwrap();
        assert_eq!(applied.ratchet_tree, second_add.ratchet_tree);
        let applied_provider = Provider::from_state(&applied.provider_state).unwrap();
        assert_eq!(
            Group::load(&applied_provider, group_id, &profile)
                .unwrap()
                .members()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn profile_pin_and_provider_decoder_reject_substitution() {
        let provider = Provider::new();
        let client = Client::generate(&provider, b"trusted:a".to_vec()).unwrap();
        let profile = GroupProfile::new(b"product/a".to_vec()).unwrap();
        Group::create(
            &provider,
            &client,
            b"profile-test-group",
            profile.clone(),
            &Identity,
            100,
        )
        .unwrap();
        let wrong = GroupProfile::new(b"product/b".to_vec()).unwrap();
        assert!(Group::load(&provider, b"profile-test-group", &wrong).is_err());
        let mut state = provider.export_state().unwrap();
        state.push(0);
        assert!(Provider::from_state(&state).is_err());
    }
}
