//! IBC token transfer context

use std::cell::RefCell;
use std::rc::Rc;

use super::common::IbcCommonContext;
use crate::ibc::apps::transfer::context::{
    TokenTransferExecutionContext, TokenTransferValidationContext,
};
use crate::ibc::apps::transfer::types::error::TokenTransferError;
use crate::ibc::apps::transfer::types::{Memo, PrefixedCoin, PrefixedDenom};
use crate::ibc::core::channel::types::error::ChannelError;
use crate::ibc::core::handler::types::error::ContextError;
use crate::ibc::core::host::types::identifiers::{ChannelId, PortId};
use crate::ledger::ibc::storage;
use crate::ledger::storage_api::token::read_denom;
use crate::types::address::{Address, InternalAddress};
use crate::types::token;
use crate::types::uint::Uint;

/// Token transfer context to handle tokens
#[derive(Debug)]
pub struct TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    inner: Rc<RefCell<C>>,
}

impl<C> TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    /// Make new token transfer context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self { inner }
    }

    /// Get the token address and the amount from PrefixedCoin. If the base
    /// denom is not an address, it returns `IbcToken`
    fn get_token_amount(
        &self,
        coin: &PrefixedCoin,
    ) -> Result<(Address, token::DenominatedAmount), TokenTransferError> {
        let token = match Address::decode(coin.denom.base_denom.as_str()) {
            Ok(token_addr) if coin.denom.trace_path.is_empty() => token_addr,
            _ => storage::ibc_token(coin.denom.to_string()),
        };

        // Convert IBC amount to Namada amount for the token
        let denom = read_denom(&*self.inner.borrow(), &token)
            .map_err(ContextError::from)?
            .unwrap_or(token::Denomination(0));
        let uint_amount = Uint(primitive_types::U256::from(coin.amount).0);
        let amount =
            token::Amount::from_uint(uint_amount, denom).map_err(|e| {
                TokenTransferError::ContextError(
                    ChannelError::Other {
                        description: format!(
                            "The IBC amount is invalid: Coin {coin}, Error {e}",
                        ),
                    }
                    .into(),
                )
            })?;
        let amount = token::DenominatedAmount::new(amount, denom);

        Ok((token, amount))
    }
}

impl<C> TokenTransferValidationContext for TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    type AccountId = Address;

    fn get_port(&self) -> Result<PortId, TokenTransferError> {
        Ok(PortId::transfer())
    }

    fn can_send_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn can_receive_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn escrow_coins_validate(
        &self,
        _from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn unescrow_coins_validate(
        &self,
        _to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn mint_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn burn_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        // validated by Multitoken VP
        Ok(())
    }

    fn denom_hash_string(&self, denom: &PrefixedDenom) -> Option<String> {
        Some(storage::calc_hash(denom.to_string()))
    }
}

impl<C> TokenTransferExecutionContext for TokenTransferContext<C>
where
    C: IbcCommonContext,
{
    fn escrow_coins_execute(
        &mut self,
        from_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        // Assumes that the coin denom is prefixed with "port-id/channel-id" or
        // has no prefix
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        let escrow = Address::Internal(InternalAddress::Ibc);
        self.inner
            .borrow_mut()
            .transfer_token(from_account, &escrow, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn unescrow_coins_execute(
        &mut self,
        to_account: &Self::AccountId,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // Assumes that the coin denom is prefixed with "port-id/channel-id" or
        // has no prefix
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        let escrow = Address::Internal(InternalAddress::Ibc);
        self.inner
            .borrow_mut()
            .transfer_token(&escrow, to_account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn mint_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // The trace path of the denom is already updated if receiving the token
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        self.inner
            .borrow_mut()
            .mint_token(account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }

    fn burn_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
        _memo: &Memo,
    ) -> Result<(), TokenTransferError> {
        let (ibc_token, amount) = self.get_token_amount(coin)?;

        // The burn is "unminting" from the minted balance
        self.inner
            .borrow_mut()
            .burn_token(account, &ibc_token, amount)
            .map_err(|e| ContextError::from(e).into())
    }
}
