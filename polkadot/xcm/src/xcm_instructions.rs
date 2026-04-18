// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Macro for generating the `Instruction<Call>` enum shared across XCM versions.
//!
//! # Motivation
//!
//! XCM versions (v4, v5, …) share the vast majority of instructions. Without this macro every
//! instruction variant — including its documentation — had to be copy-pasted verbatim into each
//! version module. That made diffs between versions unreadable and made adding a new instruction
//! expensive: each version module had to be modified independently.
//!
//! # How it works
//!
//! `define_xcm_instructions!` generates the complete `Instruction<Call>` enum together with all
//! required derives and codec attributes.  Callers supply only the parts that differ between
//! versions:
//!
//! * **`transact:`** – the field list inside the `Transact { … }` variant.  v4 uses
//!   `require_weight_at_most: Weight` while v5 uses `fallback_max_weight: Option<Weight>`.
//! * **`extra:`** – zero or more additional variants appended after the shared set.  v5 adds
//!   `PayFees`, `InitiateTransfer`, `ExecuteWithOrigin`, and `SetHints`.
//!
//! All type names referenced inside the macro body (e.g. `Assets`, `Location`, `AssetFilter`,
//! `OriginKind`, `DoubleEncoded`, `Xcm`, …) are resolved at the **call site**, so each version
//! module can import its own concrete types.
//!
//! # Adding a new shared instruction
//!
//! 1. Add the variant (with documentation) once in this file, inside the macro body.
//! 2. If the instruction introduces a type that differs between versions, follow the same pattern
//!    as `Transact` and add a new macro parameter.
//! 3. Update version-conversion `TryFrom` impls in the relevant version modules.
//!
//! # Adding a version-specific instruction
//!
//! Pass the new variant via the `extra:` parameter at the call site in the new version's module.

/// Generate the `Instruction<Call>` enum for a given XCM version.
///
/// ## Parameters
///
/// * `transact: { … }` — the struct-like field list for the `Transact` variant.
/// * `extra: { … }` *(optional)* — additional enum variants appended after the shared set.
///
/// ## Required imports at call site
///
/// The following names must be in scope when this macro is invoked:
/// `Assets`, `Asset`, `AssetFilter`, `Location`, `InteriorLocation`, `Junction`, `NetworkId`,
/// `OriginKind`, `QueryId`, `Response`, `Weight`, `WeightLimit`, `MaybeErrorCode`,
/// `QueryResponseInfo`, `DoubleEncoded`, `Xcm`, `Error`.
#[macro_export]
macro_rules! define_xcm_instructions {
	(
		transact: { $($transact_fields:tt)* }
		$(, extra: { $($extra_variants:tt)* })?
		$(,)?
	) => {
		/// Cross-Consensus Message: A message from one consensus system to another.
		///
		/// Consensus systems that may send and receive messages include blockchains and smart
		/// contracts.
		///
		/// All messages are delivered from a known *origin*, expressed as a `Location`.
		///
		/// This is the inner XCM format and is version-sensitive. Messages are typically passed
		/// using the outer XCM format, known as `VersionedXcm`.
		#[derive(
			Encode,
			Decode,
			DecodeWithMemTracking,
			TypeInfo,
			xcm_procedural::XcmWeightInfoTrait,
			xcm_procedural::Builder,
		)]
		#[derive_where(Clone, Eq, PartialEq, Debug)]
		#[codec(encode_bound())]
		#[codec(decode_bound())]
		#[codec(decode_with_mem_tracking_bound())]
		#[scale_info(bounds(), skip_type_params(Call))]
		pub enum Instruction<Call> {
			/// Withdraw asset(s) (`assets`) from the ownership of `origin` and place them into
			/// the Holding Register.
			///
			/// - `assets`: The asset(s) to be withdrawn into holding.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			#[builder(loads_holding)]
			WithdrawAsset(Assets),

			/// Asset(s) (`assets`) have been received into the ownership of this system on the
			/// `origin` system and equivalent derivatives should be placed into the Holding
			/// Register.
			///
			/// - `assets`: The asset(s) that are minted into holding.
			///
			/// Safety: `origin` must be trusted to have received and be storing `assets` such
			/// that they may later be withdrawn should this system send a corresponding message.
			///
			/// Kind: *Trusted Indication*.
			///
			/// Errors:
			#[builder(loads_holding)]
			ReserveAssetDeposited(Assets),

			/// Asset(s) (`assets`) have been destroyed on the `origin` system and equivalent
			/// assets should be created and placed into the Holding Register.
			///
			/// - `assets`: The asset(s) that are minted into the Holding Register.
			///
			/// Safety: `origin` must be trusted to have irrevocably destroyed the corresponding
			/// `assets` prior as a consequence of sending this message.
			///
			/// Kind: *Trusted Indication*.
			///
			/// Errors:
			#[builder(loads_holding)]
			ReceiveTeleportedAsset(Assets),

			/// Respond with information that the local system is expecting.
			///
			/// - `query_id`: The identifier of the query that resulted in this message being sent.
			/// - `response`: The message content.
			/// - `max_weight`: The maximum weight that handling this response should take.
			/// - `querier`: The location responsible for the initiation of the response, if there
			///   is one. In general this will tend to be the same location as the receiver of
			///   this message. NOTE: As usual, this is interpreted from the perspective of the
			///   receiving consensus system.
			///
			/// Safety: Since this is information only, there are no immediate concerns. However,
			/// it should be remembered that even if the Origin behaves reasonably, it can always
			/// be asked to make a response to a third-party chain who may or may not be expecting
			/// the response. Therefore the `querier` should be checked to match the expected
			/// value.
			///
			/// Kind: *Information*.
			///
			/// Errors:
			QueryResponse {
				#[codec(compact)]
				query_id: QueryId,
				response: Response,
				max_weight: Weight,
				querier: Option<Location>,
			},

			/// Withdraw asset(s) (`assets`) from the ownership of `origin` and place equivalent
			/// assets under the ownership of `beneficiary`.
			///
			/// - `assets`: The asset(s) to be withdrawn.
			/// - `beneficiary`: The new owner for the assets.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			TransferAsset { assets: Assets, beneficiary: Location },

			/// Withdraw asset(s) (`assets`) from the ownership of `origin` and place equivalent
			/// assets under the ownership of `dest` within this consensus system (i.e. its
			/// sovereign account).
			///
			/// Send an onward XCM message to `dest` of `ReserveAssetDeposited` with the given
			/// `xcm`.
			///
			/// - `assets`: The asset(s) to be withdrawn.
			/// - `dest`: The location whose sovereign account will own the assets and thus the
			///   effective beneficiary for the assets and the notification target for the reserve
			///   asset deposit message.
			/// - `xcm`: The instructions that should follow the `ReserveAssetDeposited`
			///   instruction, which is sent onwards to `dest`.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			TransferReserveAsset { assets: Assets, dest: Location, xcm: Xcm<()> },

			/// Apply the encoded transaction `call`, whose dispatch-origin should be `origin`
			/// as expressed by the kind of origin `origin_kind`.
			///
			/// The Transact Status Register is set according to the result of dispatching the
			/// call.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			Transact {
				origin_kind: OriginKind,
				$($transact_fields)*
				call: DoubleEncoded<Call>,
			},

			/// A message to notify about a new incoming HRMP channel. This message is meant to
			/// be sent by the relay-chain to a para.
			///
			/// - `sender`: The sender in the to-be opened channel. Also, the initiator of the
			///   channel opening.
			/// - `max_message_size`: The maximum size of a message proposed by the sender.
			/// - `max_capacity`: The maximum number of messages that can be queued in the
			///   channel.
			///
			/// Safety: The message should originate directly from the relay-chain.
			///
			/// Kind: *System Notification*
			HrmpNewChannelOpenRequest {
				#[codec(compact)]
				sender: u32,
				#[codec(compact)]
				max_message_size: u32,
				#[codec(compact)]
				max_capacity: u32,
			},

			/// A message to notify about that a previously sent open channel request has been
			/// accepted by the recipient. That means that the channel will be opened during the
			/// next relay-chain session change. This message is meant to be sent by the
			/// relay-chain to a para.
			///
			/// Safety: The message should originate directly from the relay-chain.
			///
			/// Kind: *System Notification*
			///
			/// Errors:
			HrmpChannelAccepted {
				/// NOTE: We keep this as a structured item to a) keep it consistent with the
				/// other Hrmp items; and b) because the field's meaning is not
				/// obvious/mentioned from the item name.
				#[codec(compact)]
				recipient: u32,
			},

			/// A message to notify that the other party in an open channel decided to close it.
			/// In particular, `initiator` is going to close the channel opened from `sender` to
			/// the `recipient`. The close will be enacted at the next relay-chain session change.
			/// This message is meant to be sent by the relay-chain to a para.
			///
			/// Safety: The message should originate directly from the relay-chain.
			///
			/// Kind: *System Notification*
			///
			/// Errors:
			HrmpChannelClosing {
				#[codec(compact)]
				initiator: u32,
				#[codec(compact)]
				sender: u32,
				#[codec(compact)]
				recipient: u32,
			},

			/// Clear the origin.
			///
			/// This may be used by the XCM author to ensure that later instructions cannot
			/// command the authority of the origin (e.g. if they are being relayed from an
			/// untrusted source, as often the case with `ReserveAssetDeposited`).
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			ClearOrigin,

			/// Mutate the origin to some interior location.
			///
			/// Kind: *Command*
			///
			/// Errors:
			DescendOrigin(InteriorLocation),

			/// Immediately report the contents of the Error Register to the given destination
			/// via XCM.
			///
			/// A `QueryResponse` message of type `ExecutionOutcome` is sent to the described
			/// destination.
			///
			/// - `response_info`: Information for making the response.
			///
			/// Kind: *Command*
			///
			/// Errors:
			ReportError(QueryResponseInfo),

			/// Remove the asset(s) (`assets`) from the Holding Register and place equivalent
			/// assets under the ownership of `beneficiary` within this consensus system.
			///
			/// - `assets`: The asset(s) to remove from holding.
			/// - `beneficiary`: The new owner for the assets.
			///
			/// Kind: *Command*
			///
			/// Errors:
			DepositAsset { assets: AssetFilter, beneficiary: Location },

			/// Remove the asset(s) (`assets`) from the Holding Register and place equivalent
			/// assets under the ownership of `dest` within this consensus system (i.e. deposit
			/// them into its sovereign account).
			///
			/// Send an onward XCM message to `dest` of `ReserveAssetDeposited` with the given
			/// `effects`.
			///
			/// - `assets`: The asset(s) to remove from holding.
			/// - `dest`: The location whose sovereign account will own the assets and thus the
			///   effective beneficiary for the assets and the notification target for the reserve
			///   asset deposit message.
			/// - `xcm`: The orders that should follow the `ReserveAssetDeposited` instruction
			///   which is sent onwards to `dest`.
			///
			/// Kind: *Command*
			///
			/// Errors:
			DepositReserveAsset { assets: AssetFilter, dest: Location, xcm: Xcm<()> },

			/// Remove the asset(s) (`want`) from the Holding Register and replace them with
			/// alternative assets.
			///
			/// The minimum amount of assets to be received into the Holding Register for the
			/// order not to fail may be stated.
			///
			/// - `give`: The maximum amount of assets to remove from holding.
			/// - `want`: The minimum amount of assets which `give` should be exchanged for.
			/// - `maximal`: If `true`, then prefer to give as much as possible up to the limit
			///   of `give` and receive accordingly more. If `false`, then prefer to give as
			///   little as possible in order to receive as little as possible while receiving at
			///   least `want`.
			///
			/// Kind: *Command*
			///
			/// Errors:
			ExchangeAsset { give: AssetFilter, want: Assets, maximal: bool },

			/// Remove the asset(s) (`assets`) from holding and send a `WithdrawAsset` XCM
			/// message to a reserve location.
			///
			/// - `assets`: The asset(s) to remove from holding.
			/// - `reserve`: A valid location that acts as a reserve for all asset(s) in
			///   `assets`. The sovereign account of this consensus system *on the reserve
			///   location* will have appropriate assets withdrawn and `effects` will be executed
			///   on them. There will typically be only one valid location on any given
			///   asset/chain combination.
			/// - `xcm`: The instructions to execute on the assets once withdrawn *on the reserve
			///   location*.
			///
			/// Kind: *Command*
			///
			/// Errors:
			InitiateReserveWithdraw { assets: AssetFilter, reserve: Location, xcm: Xcm<()> },

			/// Remove the asset(s) (`assets`) from holding and send a
			/// `ReceiveTeleportedAsset` XCM message to a `dest` location.
			///
			/// - `assets`: The asset(s) to remove from holding.
			/// - `dest`: A valid location that respects teleports coming from this location.
			/// - `xcm`: The instructions to execute on the assets once arrived *on the
			///   destination location*.
			///
			/// NOTE: The `dest` location *MUST* respect this origin as a valid teleportation
			/// origin for all `assets`. If it does not, then the assets may be lost.
			///
			/// Kind: *Command*
			///
			/// Errors:
			InitiateTeleport { assets: AssetFilter, dest: Location, xcm: Xcm<()> },

			/// Report to a given destination the contents of the Holding Register.
			///
			/// A `QueryResponse` message of type `Assets` is sent to the described destination.
			///
			/// - `response_info`: Information for making the response.
			/// - `assets`: A filter for the assets that should be reported back. The assets
			///   reported back will be, asset-wise, *the lesser of this value and the holding
			///   register*. No wildcards will be used when reporting assets back.
			///
			/// Kind: *Command*
			///
			/// Errors:
			ReportHolding { response_info: QueryResponseInfo, assets: AssetFilter },

			/// Pay for the execution of some XCM `xcm` and `orders` with up to `weight`
			/// picoseconds of execution time, paying for this with up to `fees` from the Holding
			/// Register.
			///
			/// - `fees`: The asset(s) to remove from the Holding Register to pay for fees.
			/// - `weight_limit`: The maximum amount of weight to purchase; this must be at least
			///   the expected maximum weight of the total XCM to be executed for the
			///   `AllowTopLevelPaidExecutionFrom` barrier to allow the XCM be executed.
			///
			/// Kind: *Command*
			///
			/// Errors:
			#[builder(pays_fees)]
			BuyExecution { fees: Asset, weight_limit: WeightLimit },

			/// Refund any surplus weight previously bought with `BuyExecution`.
			///
			/// Kind: *Command*
			///
			/// Errors: None.
			RefundSurplus,

			/// Set the Error Handler Register. This is code that should be called in the case
			/// of an error happening.
			///
			/// An error occurring within execution of this code will _NOT_ result in the error
			/// register being set, nor will an error handler be called due to it. The error
			/// handler and appendix may each still be set.
			///
			/// The apparent weight of this instruction is inclusive of the inner `Xcm`; the
			/// executing weight however includes only the difference between the previous handler
			/// and the new handler, which can reasonably be negative, which would result in a
			/// surplus.
			///
			/// Kind: *Command*
			///
			/// Errors: None.
			SetErrorHandler(Xcm<Call>),

			/// Set the Appendix Register. This is code that should be called after code
			/// execution (including the error handler if any) is finished. This will be called
			/// regardless of whether an error occurred.
			///
			/// Any error occurring due to execution of this code will result in the error
			/// register being set, and the error handler (if set) firing.
			///
			/// The apparent weight of this instruction is inclusive of the inner `Xcm`; the
			/// executing weight however includes only the difference between the previous
			/// appendix and the new appendix, which can reasonably be negative, which would
			/// result in a surplus.
			///
			/// Kind: *Command*
			///
			/// Errors: None.
			SetAppendix(Xcm<Call>),

			/// Clear the Error Register.
			///
			/// Kind: *Command*
			///
			/// Errors: None.
			ClearError,

			/// Create some assets which are being held on behalf of the origin.
			///
			/// - `assets`: The assets which are to be claimed. This must match exactly with the
			///   assets claimable by the origin of the ticket.
			/// - `ticket`: The ticket of the asset; this is an abstract identifier to help
			///   locate the asset.
			///
			/// Kind: *Command*
			///
			/// Errors:
			#[builder(loads_holding)]
			ClaimAsset { assets: Assets, ticket: Location },

			/// Always throws an error of type `Trap`.
			///
			/// Kind: *Command*
			///
			/// Errors:
			/// - `Trap`: All circumstances, whose inner value is the same as this item's inner
			///   value.
			Trap(#[codec(compact)] u64),

			/// Ask the destination system to respond with the most recent version of XCM that
			/// they support in a `QueryResponse` instruction. Any changes to this should also
			/// elicit similar responses when they happen.
			///
			/// - `query_id`: An identifier that will be replicated into the returned XCM
			///   message.
			/// - `max_response_weight`: The maximum amount of weight that the `QueryResponse`
			///   item which is sent as a reply may take to execute. NOTE: If this is
			///   unexpectedly large then the response may not execute at all.
			///
			/// Kind: *Command*
			///
			/// Errors: *Fallible*
			SubscribeVersion {
				#[codec(compact)]
				query_id: QueryId,
				max_response_weight: Weight,
			},

			/// Cancel the effect of a previous `SubscribeVersion` instruction.
			///
			/// Kind: *Command*
			///
			/// Errors: *Fallible*
			UnsubscribeVersion,

			/// Reduce Holding by up to the given assets.
			///
			/// Holding is reduced by as much as possible up to the assets in the parameter. It
			/// is not an error if the Holding does not contain the assets (to make this an
			/// error, use `ExpectAsset` prior).
			///
			/// Kind: *Command*
			///
			/// Errors: *Infallible*
			BurnAsset(Assets),

			/// Throw an error if Holding does not contain at least the given assets.
			///
			/// Kind: *Command*
			///
			/// Errors:
			/// - `ExpectationFalse`: If Holding Register does not contain the assets in the
			///   parameter.
			ExpectAsset(Assets),

			/// Ensure that the Origin Register equals some given value and throw an error if
			/// not.
			///
			/// Kind: *Command*
			///
			/// Errors:
			/// - `ExpectationFalse`: If Origin Register is not equal to the parameter.
			ExpectOrigin(Option<Location>),

			/// Ensure that the Error Register equals some given value and throw an error if not.
			///
			/// Kind: *Command*
			///
			/// Errors:
			/// - `ExpectationFalse`: If the value of the Error Register is not equal to the
			///   parameter.
			ExpectError(Option<(u32, Error)>),

			/// Ensure that the Transact Status Register equals some given value and throw an
			/// error if not.
			///
			/// Kind: *Command*
			///
			/// Errors:
			/// - `ExpectationFalse`: If the value of the Transact Status Register is not equal
			///   to the parameter.
			ExpectTransactStatus(MaybeErrorCode),

			/// Query the existence of a particular pallet type.
			///
			/// - `module_name`: The module name of the pallet to query.
			/// - `response_info`: Information for making the response.
			///
			/// Sends a `QueryResponse` to Origin whose data field `PalletsInfo` containing the
			/// information of all pallets on the local chain whose name is equal to `name`. This
			/// is empty in the case that the local chain is not based on Substrate Frame.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*
			///
			/// Errors: *Fallible*.
			QueryPallet { module_name: Vec<u8>, response_info: QueryResponseInfo },

			/// Ensure that a particular pallet with a particular version exists.
			///
			/// - `index: Compact`: The index which identifies the pallet. An error if no pallet
			///   exists at this index.
			/// - `name: Vec<u8>`: Name which must be equal to the name of the pallet.
			/// - `module_name: Vec<u8>`: Module name which must be equal to the name of the
			///   module in which the pallet exists.
			/// - `crate_major: Compact`: Version number which must be equal to the major version
			///   of the crate which implements the pallet.
			/// - `min_crate_minor: Compact`: Version number which must be at most the minor
			///   version of the crate which implements the pallet.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*
			///
			/// Errors:
			/// - `ExpectationFalse`: In case any of the expectations are broken.
			ExpectPallet {
				#[codec(compact)]
				index: u32,
				name: Vec<u8>,
				module_name: Vec<u8>,
				#[codec(compact)]
				crate_major: u32,
				#[codec(compact)]
				min_crate_minor: u32,
			},

			/// Send a `QueryResponse` message containing the value of the Transact Status
			/// Register to some destination.
			///
			/// - `query_response_info`: The information needed for constructing and sending the
			///   `QueryResponse` message.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*
			///
			/// Errors: *Fallible*.
			ReportTransactStatus(QueryResponseInfo),

			/// Set the Transact Status Register to its default, cleared, value.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*
			///
			/// Errors: *Infallible*.
			ClearTransactStatus,

			/// Set the Origin Register to be some child of the Universal Ancestor.
			///
			/// Safety: Should only be usable if the Origin is trusted to represent the Universal
			/// Ancestor child in general. In general, no Origin should be able to represent the
			/// Universal Ancestor child which is the root of the local consensus system since it
			/// would by extension allow it to act as any location within the local consensus.
			///
			/// The `Junction` parameter should generally be a `GlobalConsensus` variant since
			/// it is only these which are children of the Universal Ancestor.
			///
			/// Kind: *Command*
			///
			/// Errors: *Fallible*.
			UniversalOrigin(Junction),

			/// Send a message on to Non-Local Consensus system.
			///
			/// This will tend to utilize some extra-consensus mechanism, the obvious one being a
			/// bridge. A fee may be charged; this may be determined based on the contents of
			/// `xcm`. It will be taken from the Holding register.
			///
			/// - `network`: The remote consensus system to which the message should be exported.
			/// - `destination`: The location relative to the remote consensus system to which
			///   the message should be sent on arrival.
			/// - `xcm`: The message to be exported.
			///
			/// As an example, to export a message for execution on Statemine (parachain #1000
			/// in the Kusama network), you would call with `network: NetworkId::Kusama` and
			/// `destination: [Parachain(1000)].into()`. Alternatively, to export a message for
			/// execution on Polkadot, you would call with `network: NetworkId::Polkadot` and
			/// `destination: Here`.
			///
			/// Kind: *Command*
			///
			/// Errors: *Fallible*.
			ExportMessage { network: NetworkId, destination: InteriorLocation, xcm: Xcm<()> },

			/// Lock the locally held asset and prevent further transfer or withdrawal.
			///
			/// This restriction may be removed by the `UnlockAsset` instruction being called
			/// with an Origin of `unlocker` and a `target` equal to the current `Origin`.
			///
			/// If the locking is successful, then a `NoteUnlockable` instruction is sent to
			/// `unlocker`.
			///
			/// - `asset`: The asset(s) which should be locked.
			/// - `unlocker`: The value which the Origin must be for a corresponding
			///   `UnlockAsset` instruction to work.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			LockAsset { asset: Asset, unlocker: Location },

			/// Remove the lock over `asset` on this chain and (if nothing else is preventing
			/// it) allow the asset to be transferred.
			///
			/// - `asset`: The asset to be unlocked.
			/// - `target`: The owner of the asset on the local chain.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			UnlockAsset { asset: Asset, target: Location },

			/// Asset (`asset`) has been locked on the `origin` system and may not be
			/// transferred. It may only be unlocked with the receipt of the `UnlockAsset`
			/// instruction from this chain.
			///
			/// - `asset`: The asset(s) which are now unlockable from this origin.
			/// - `owner`: The owner of the asset on the chain in which it was locked. This may
			///   be a location specific to the origin network.
			///
			/// Safety: `origin` must be trusted to have locked the corresponding `asset` prior
			/// as a consequence of sending this message.
			///
			/// Kind: *Trusted Indication*.
			///
			/// Errors:
			NoteUnlockable { asset: Asset, owner: Location },

			/// Send an `UnlockAsset` instruction to the `locker` for the given `asset`.
			///
			/// This may fail if the local system is making use of the fact that the asset is
			/// locked or, of course, if there is no record that the asset actually is locked.
			///
			/// - `asset`: The asset(s) to be unlocked.
			/// - `locker`: The location from which a previous `NoteUnlockable` was sent and to
			///   which an `UnlockAsset` should be sent.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			RequestUnlock { asset: Asset, locker: Location },

			/// Sets the Fees Mode Register.
			///
			/// - `jit_withdraw`: The fees mode item; if set to `true` then fees for any
			///   instructions are withdrawn as needed using the same mechanism as
			///   `WithdrawAssets`.
			///
			/// Kind: *Command*.
			///
			/// Errors:
			SetFeesMode { jit_withdraw: bool },

			/// Set the Topic Register.
			///
			/// The 32-byte array identifier in the parameter is not guaranteed to be unique; if
			/// such a property is desired, it is up to the code author to enforce uniqueness.
			///
			/// Safety: No concerns.
			///
			/// Kind: *Command*
			///
			/// Errors:
			SetTopic([u8; 32]),

			/// Clear the Topic Register.
			///
			/// Kind: *Command*
			///
			/// Errors: None.
			ClearTopic,

			/// Alter the current Origin to another given origin.
			///
			/// Kind: *Command*
			///
			/// Errors: If the existing state would not allow such a change.
			AliasOrigin(Location),

			/// A directive to indicate that the origin expects free execution of the message.
			///
			/// At execution time, this instruction just does a check on the Origin register.
			/// However, at the barrier stage messages starting with this instruction can be
			/// disregarded if the origin is not acceptable for free execution or the
			/// `weight_limit` is `Limited` and insufficient.
			///
			/// Kind: *Indication*
			///
			/// Errors: If the given origin is `Some` and not equal to the current Origin
			/// register.
			UnpaidExecution { weight_limit: WeightLimit, check_origin: Option<Location> },

			// Version-specific instructions supplied by the caller:
			$($($extra_variants)*)?
		}
	};
}
