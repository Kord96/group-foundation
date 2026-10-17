//! Exact ownership of OpenMLS MemoryStorage v1 keys. Product sidecar ownership
//! is supplied separately; Group never interprets product storage values.
use super::*;
use std::collections::BTreeSet;

/// Reserved opaque sidecar namespace; native OpenMLS keys cannot collide.
pub const SIDECAR_PREFIX: &[u8] = b"group-foundation.sidecar.";

impl Provider {
    fn validate_product_record_key(key: &[u8]) -> Result<()> {
        // Native OpenMLS keys never start with this product namespace. Products
        // own the opaque suffix and value; this API cannot overwrite MLS state.
        if !key.starts_with(SIDECAR_PREFIX)
            || key.len() <= SIDECAR_PREFIX.len()
            || key.len() > MAX_PROVIDER_KEY_BYTES
        {
            return Err(GroupError::Invalid(
                "opaque product record key exceeds its namespace or bound",
            ));
        }
        Ok(())
    }

    pub fn product_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Self::validate_product_record_key(key)?;
        Ok(self
            .storage
            .values
            .read()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?
            .get(key)
            .cloned())
    }

    pub fn product_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Self::validate_product_record_key(prefix)?;
        Ok(self
            .storage
            .values
            .read()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    pub fn store_product_record(&self, key: &[u8], value: Vec<u8>) -> Result<()> {
        Self::validate_product_record_key(key)?;
        let mut values = self
            .storage
            .values
            .write()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        let total = values
            .iter()
            .filter(|(existing, _)| existing.as_slice() != key)
            .try_fold(13usize, |total, (key, value)| {
                total.checked_add(16 + key.len() + value.len())
            })
            .and_then(|total| total.checked_add(16 + key.len() + value.len()));
        if value.len() > MAX_PROVIDER_STATE_BYTES
            || total.is_none_or(|total| total > MAX_PROVIDER_STATE_BYTES)
            || (!values.contains_key(key) && values.len() >= MAX_PROVIDER_ENTRIES)
        {
            return Err(GroupError::Invalid(
                "opaque product record exceeds provider capacity",
            ));
        }
        values.insert(key.to_vec(), value);
        Ok(())
    }

    pub fn product_storage_is_owned(key: &[u8], group_id: &[u8]) -> Result<bool> {
        if group_id.is_empty() || group_id.len() > 255 || key.len() > MAX_PROVIDER_KEY_BYTES {
            return Err(GroupError::Invalid(
                "native storage ownership input exceeds its bound",
            ));
        }
        let id = GroupId::from_slice(group_id);
        let encoded = serde_json::to_vec(&id).map_err(mls)?;
        let labels: &[&[u8]] = &[
            b"ApplicationExportTree",
            b"Tree",
            b"GroupContext",
            b"InterimTranscriptHash",
            b"ConfirmationTag",
            b"MlsGroupJoinConfig",
            b"OwnLeafNodes",
            b"GroupState",
            b"ProposalQueueRefs",
            b"OwnLeafNodeIndex",
            b"EpochSecrets",
            b"ResumptionPsk",
            b"MessageSecrets",
        ];
        for label in labels {
            if key == [*label, &encoded, &1u16.to_be_bytes()].concat() {
                return Ok(true);
            }
        }
        if let Some(rest) = key.strip_prefix(b"EpochKeyPairs") {
            if let Some(id) = rest.strip_suffix(&1u16.to_be_bytes()) {
                if let Some(suffix) = id.strip_prefix(encoded.as_slice()) {
                    return Ok(!suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit));
                }
            }
        }
        if let Some(rest) = key.strip_prefix(b"QueuedProposal") {
            if let Some(encoded_key) = rest.strip_suffix(&1u16.to_be_bytes()) {
                let value: serde_json::Value = serde_json::from_slice(encoded_key).map_err(mls)?;
                return Ok(value.as_array().is_some_and(|parts| {
                    parts.len() == 2
                        && parts[0] == serde_json::to_value(&id).expect("group ID serializes")
                }));
            }
        }
        Ok(false)
    }

    /// Copy only this group's native namespace and product-selected sidecars.
    pub fn retain_product_storage(
        &self,
        group_id: &[u8],
        owns_sidecar: impl Fn(&[u8]) -> bool,
    ) -> Result<Self> {
        let clean = self.detached()?;
        let mut values = clean
            .storage
            .values
            .write()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        let mut unowned = Vec::new();
        for key in values.keys() {
            if !Self::product_storage_is_owned(key, group_id)?
                && !(key.starts_with(SIDECAR_PREFIX) && owns_sidecar(key))
            {
                unowned.push(key.clone());
            }
        }
        for key in unowned {
            values.remove(&key);
        }
        drop(values);
        Ok(clean)
    }

    /// Construct an installation in detached custody. A candidate must change
    /// only this group's native keys and explicitly owned product sidecars.
    pub fn install_product_branch(
        &self,
        anchor: &Provider,
        selected: &Provider,
        group_id: &[u8],
        owns_sidecar: impl Fn(&[u8]) -> bool,
    ) -> Result<Self> {
        let anchor_values = anchor
            .storage
            .values
            .read()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        let selected_values = selected
            .storage
            .values
            .read()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        let keys: BTreeSet<_> = anchor_values.keys().chain(selected_values.keys()).collect();
        for key in keys {
            if anchor_values.get(key) != selected_values.get(key)
                && !Self::product_storage_is_owned(key, group_id)?
                && !(key.starts_with(SIDECAR_PREFIX) && owns_sidecar(key))
            {
                return Err(GroupError::Invalid(
                    "native branch attempts foreign storage mutation",
                ));
            }
        }
        let installation = self.detached()?;
        let mut values = installation
            .storage
            .values
            .write()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        let mut owned = Vec::new();
        for key in values.keys() {
            if Self::product_storage_is_owned(key, group_id)?
                || (key.starts_with(SIDECAR_PREFIX) && owns_sidecar(key))
            {
                owned.push(key.clone());
            }
        }
        let mut selected_owned = Vec::new();
        for (key, value) in selected_values.iter() {
            if Self::product_storage_is_owned(key, group_id)?
                || (key.starts_with(SIDECAR_PREFIX) && owns_sidecar(key))
            {
                selected_owned.push((key.clone(), value.clone()));
            }
        }
        for key in owned {
            values.remove(&key);
        }
        values.extend(selected_owned);
        drop(values);
        // Bound the complete candidate before exposing it for installation.
        installation.export_state()?;
        Ok(installation)
    }

    pub fn prune_product_storage(
        &self,
        group_id: &[u8],
        owns_sidecar: impl Fn(&[u8]) -> bool,
    ) -> Result<()> {
        let mut values = self
            .storage
            .values
            .write()
            .map_err(|_| GroupError::Invalid("provider storage lock poisoned"))?;
        let mut owned = Vec::new();
        for key in values.keys() {
            if Self::product_storage_is_owned(key, group_id)?
                || (key.starts_with(SIDECAR_PREFIX) && owns_sidecar(key))
            {
                owned.push(key.clone());
            }
        }
        for key in owned {
            values.remove(&key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_install_rejects_foreign_native_and_product_mutation_without_live_effects() {
        let provider = Provider::new();
        let group_id = b"owned";
        let native = |id: &[u8]| {
            [
                b"GroupContext".as_slice(),
                &serde_json::to_vec(&GroupId::from_slice(id)).unwrap(),
                &1u16.to_be_bytes(),
            ]
            .concat()
        };
        let owned_key = native(group_id);
        let foreign_key = native(b"foreign");
        provider
            .storage
            .values
            .write()
            .unwrap()
            .extend([(owned_key.clone(), vec![1]), (foreign_key.clone(), vec![2])]);
        provider
            .store_product_record(b"group-foundation.sidecar.test.owned", vec![3])
            .unwrap();
        provider
            .store_product_record(b"group-foundation.sidecar.test.foreign", vec![4])
            .unwrap();
        let before = provider.export_state().unwrap();
        let anchor = provider.detached().unwrap();
        let selected = provider.detached().unwrap();
        selected
            .storage
            .values
            .write()
            .unwrap()
            .insert(foreign_key.clone(), vec![5]);
        let owns = |key: &[u8]| key == b"group-foundation.sidecar.test.owned";
        assert!(
            provider
                .install_product_branch(&anchor, &selected, group_id, owns)
                .is_err()
        );
        assert!(
            provider
                .install_product_branch(&anchor, &selected, group_id, |_| true)
                .is_err()
        );
        selected
            .storage
            .values
            .write()
            .unwrap()
            .insert(foreign_key.clone(), vec![2]);
        selected
            .store_product_record(b"group-foundation.sidecar.test.foreign", vec![5])
            .unwrap();
        assert!(
            provider
                .install_product_branch(&anchor, &selected, group_id, owns)
                .is_err()
        );
        selected
            .store_product_record(b"group-foundation.sidecar.test.foreign", vec![4])
            .unwrap();
        selected
            .storage
            .values
            .write()
            .unwrap()
            .insert(owned_key.clone(), vec![6]);
        let installation = provider
            .install_product_branch(&anchor, &selected, group_id, owns)
            .unwrap();
        assert_eq!(
            installation.storage.values.read().unwrap().get(&owned_key),
            Some(&vec![6])
        );
        assert_eq!(
            installation
                .storage
                .values
                .read()
                .unwrap()
                .get(&foreign_key),
            Some(&vec![2])
        );
        assert_eq!(provider.export_state().unwrap(), before);
        assert!(provider.store_product_record(&owned_key, vec![7]).is_err());
        assert!(
            provider
                .store_product_record(
                    b"group-foundation.sidecar.test.owned",
                    vec![0; MAX_PROVIDER_STATE_BYTES]
                )
                .is_err()
        );
        assert_eq!(provider.export_state().unwrap(), before);
        let mut collision = owned_key.clone();
        collision.push(0);
        assert!(!Provider::product_storage_is_owned(&collision, group_id).unwrap());
        assert!(!Provider::product_storage_is_owned(&foreign_key, group_id).unwrap());
    }
}
