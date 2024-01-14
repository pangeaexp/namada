//! IBC Non-Fungible token transfer context

use std::cell::RefCell;
use std::rc::Rc;

use super::common::IbcCommonContext;
use crate::ibc::apps::nft_transfer::context::{
    NftTransferExecutionContext, NftTransferValidationContext,
};
use crate::ibc::apps::nft_transfer::types::error::NftTransferError;
use crate::ibc::apps::nft_transfer::types::{
    ClassData, ClassUri, Memo, PrefixedClassId, TokenData, TokenId, TokenUri,
    PORT_ID_STR,
};
use crate::ibc::core::handler::types::error::ContextError;
use crate::ibc::core::host::types::identifiers::{ChannelId, PortId};
use crate::ledger::ibc::storage;
use crate::types::address::Address;
use crate::types::ibc::{NftClass, NftMetadata, IBC_ESCROW_ADDRESS};
use crate::types::token::DenominatedAmount;

/// NFT transfer context to handle tokens
#[derive(Debug)]
pub struct NftTransferContext<C>
where
    C: IbcCommonContext,
{
    inner: Rc<RefCell<C>>,
}

impl<C> NftTransferContext<C>
where
    C: IbcCommonContext,
{
    /// Make new NFT transfer context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self { inner }
    }
}

impl<C> NftTransferValidationContext for NftTransferContext<C>
where
    C: IbcCommonContext,
{
    type AccountId = Address;
    type Nft = NftMetadata;
    type NftClass = NftClass;

    fn get_port(&self) -> Result<PortId, NftTransferError> {
        Ok(PORT_ID_STR.parse().expect("the ID should be parsable"))
    }

    fn can_send_nft(&self) -> Result<(), NftTransferError> {
        Ok(())
    }

    fn can_receive_nft(&self) -> Result<(), NftTransferError> {
        Ok(())
    }

    /// Validates that the NFT can be created or updated successfully.
    fn create_or_update_class_validate(
        &self,
        class_id: &PrefixedClassId,
        _class_uri: &ClassUri,
        _class_data: &ClassData,
    ) -> Result<(), NftTransferError> {
        match self.get_nft_class(class_id) {
            Err(NftTransferError::NftClassNotFound) => Ok(()),
            Err(e) => Err(e),
            Ok(class) if class.class_id != *class_id => {
                Err(NftTransferError::Other(format!(
                    "The existing Class ID mismatched: class_id {class_id}"
                )))
            }
            _ => Ok(()),
        }
    }

    fn escrow_nft_validate(
        &self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        // Assumes that the class ID is prefixed with "port-id/channel-id" or
        // has no prefix

        // The metadata should exist
        self.get_nft(class_id, token_id)?;

        // Check the account owns the NFT
        if self
            .inner
            .borrow()
            .is_nft_owned(class_id, token_id, from_account)?
        {
            Ok(())
        } else {
            Err(NftTransferError::Other(format!(
                "The sender balance is invalid: sender {from_account}, \
                 class_id {class_id}, token_id {token_id}"
            )))
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn unescrow_nft_validate(
        &self,
        _to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<(), NftTransferError> {
        // Assumes that the class ID is prefixed with "port-id/channel-id" or
        // has no prefix

        // The metadata should exist
        self.get_nft(class_id, token_id)?;

        // Check the NFT is escrowed
        if self.inner.borrow().is_nft_owned(
            class_id,
            token_id,
            &IBC_ESCROW_ADDRESS,
        )? {
            Ok(())
        } else {
            Err(NftTransferError::Other(format!(
                "The escrow balance is invalid: class_id {class_id}, token_id \
                 {token_id}"
            )))
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn mint_nft_validate(
        &self,
        _account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _token_uri: &TokenUri,
        _token_data: &TokenData,
    ) -> Result<(), NftTransferError> {
        match self.get_nft(class_id, token_id) {
            Err(NftTransferError::NftNotFound) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(NftTransferError::Other(format!(
                "Metadata should not exist for this NFT: class_id {class_id}, \
                 token_id {token_id}"
            ))),
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn burn_nft_validate(
        &self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        // Metadata should exist
        self.get_nft(class_id, token_id)?;

        // Check the account owns the NFT
        if self
            .inner
            .borrow()
            .is_nft_owned(class_id, token_id, account)?
        {
            Ok(())
        } else {
            Err(NftTransferError::Other(format!(
                "The sender balance is invalid: sender {account}, class_id \
                 {class_id}, token_id {token_id}"
            )))
        }
        // Balance changes will be validated by Multitoken VP
    }

    fn class_hash_string(&self, class_id: &PrefixedClassId) -> Option<String> {
        Some(storage::calc_hash(class_id.to_string()))
    }

    /// Returns the NFT
    fn get_nft(
        &self,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<Self::Nft, NftTransferError> {
        match self.inner.borrow().nft_metadata(class_id, token_id) {
            Ok(Some(nft)) => Ok(nft),
            Ok(None) => Err(NftTransferError::NftNotFound),
            Err(e) => Err(NftTransferError::ContextError(e)),
        }
    }

    /// Returns the NFT class
    fn get_nft_class(
        &self,
        class_id: &PrefixedClassId,
    ) -> Result<Self::NftClass, NftTransferError> {
        match self.inner.borrow().nft_class(class_id) {
            Ok(Some(class)) => Ok(class),
            Ok(None) => Err(NftTransferError::NftClassNotFound),
            Err(e) => Err(NftTransferError::ContextError(e)),
        }
    }
}

impl<C> NftTransferExecutionContext for NftTransferContext<C>
where
    C: IbcCommonContext,
{
    fn create_or_update_class_execute(
        &self,
        class_id: &PrefixedClassId,
        class_uri: &ClassUri,
        class_data: &ClassData,
    ) -> Result<(), NftTransferError> {
        let class = NftClass {
            class_id: class_id.clone(),
            class_uri: class_uri.clone(),
            class_data: class_data.clone(),
        };
        self.inner
            .borrow_mut()
            .store_nft_class(class_id, class)
            .map_err(|e| e.into())
    }

    fn escrow_nft_execute(
        &mut self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        let ibc_token = storage::ibc_token_for_nft(class_id, token_id);

        self.inner
            .borrow_mut()
            .transfer_token(
                from_account,
                &IBC_ESCROW_ADDRESS,
                &ibc_token,
                DenominatedAmount::new(1.into(), 0.into()),
            )
            .map_err(|e| ContextError::from(e).into())
    }

    /// Executes the unescrow of the NFT in a user account.
    fn unescrow_nft_execute(
        &mut self,
        to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<(), NftTransferError> {
        let ibc_token = storage::ibc_token_for_nft(class_id, token_id);

        self.inner
            .borrow_mut()
            .transfer_token(
                &IBC_ESCROW_ADDRESS,
                to_account,
                &ibc_token,
                DenominatedAmount::new(1.into(), 0.into()),
            )
            .map_err(|e| ContextError::from(e).into())
    }

    fn mint_nft_execute(
        &mut self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        token_uri: &TokenUri,
        token_data: &TokenData,
    ) -> Result<(), NftTransferError> {
        let ibc_token = storage::ibc_token_for_nft(class_id, token_id);

        // create or update the metadata
        let metadata = NftMetadata {
            class_id: class_id.clone(),
            token_id: token_id.clone(),
            token_uri: token_uri.clone(),
            token_data: token_data.clone(),
        };
        self.inner
            .borrow_mut()
            .store_nft_metadata(class_id, token_id, metadata)?;

        self.inner
            .borrow_mut()
            .mint_token(
                account,
                &ibc_token,
                DenominatedAmount::new(1.into(), 0.into()),
            )
            .map_err(|e| ContextError::from(e).into())
    }

    fn burn_nft_execute(
        &mut self,
        account: &Self::AccountId,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        _memo: &Memo,
    ) -> Result<(), NftTransferError> {
        let ibc_token = storage::ibc_token_for_nft(class_id, token_id);

        self.inner
            .borrow_mut()
            .delete_nft_metadata(class_id, token_id)?;

        self.inner
            .borrow_mut()
            .burn_token(
                account,
                &ibc_token,
                DenominatedAmount::new(1.into(), 0.into()),
            )
            .map_err(|e| ContextError::from(e).into())
    }
}
