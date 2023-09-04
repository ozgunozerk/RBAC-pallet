//! # Access Control Pallet
//!
//! Implements Access controls for allowing specific addresses to sign extrinsics and permissions for assigning access.
#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod traits;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use frame_system::{ensure_signed, pallet_prelude::OriginFor};

#[cfg(feature = "std")]
use frame_support::serde::{Deserialize, Serialize};
use frame_support::{
    dispatch::{DispatchInfo, PostDispatchInfo},
    traits::GetCallMetadata,
};

use scale_info::TypeInfo;
use sp_runtime::{
    traits::{DispatchInfoOf, Dispatchable, SignedExtension},
    transaction_validity::{InvalidTransaction, TransactionValidity, TransactionValidityError},
    BoundedVec, RuntimeDebug,
};
use sp_std::prelude::*;
use traits::{TraitError, VerifyAccess};

/// We have 2 permissions:
/// - `execute` is for being able to call the extrinsic
/// - `manage` is for being able to assign accounts to `execute` and `manage`
#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode, TypeInfo, Default)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Permission {
    #[default]
    Execute,
    Manage,
}

/// Actions are extrinsics, that are callable from pallets
/// each action also has the permission field [`Permission`]
#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Action {
    pub pallet: Vec<u8>,
    pub extrinsic: Vec<u8>,
    pub permission: Permission,
}

/// AccessControl is defined via a permission action, and the users with privileges
#[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct AccessControl<T> {
    pub action: Action,
    pub accounts: Vec<T>,
}

/// RBAC pallet
///
/// that can create/remove the following:
/// - actions
/// - permissions
/// - admins
#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
    use sp_std::convert::TryInto;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Maximum number of admins allowed
        type MaxAdmins: Get<u32>;

        /// Maximum number of controls allowed
        type MaxControls: Get<u32>;

        /// Maximum number of accounts per actions
        type MaxAccountsPerAction: Get<u32>;

        /// The Event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Origin for adding or removing access_controls and permissions.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Admins who manage the assignment of access
    #[pallet::storage]
    #[pallet::getter(fn admins)]
    pub type Admins<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ()>;

    /// Store access controls for Executing and managing a specific extrinsic on a pallet.
    #[pallet::storage]
    #[pallet::getter(fn access_controls)]
    pub type AccessControls<T: Config> =
        StorageMap<_, Blake2_128Concat, Action, BoundedVec<T::AccountId, T::MaxAccountsPerAction>>;

    /// Config for genesis that will bootstrap other permissions
    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub admins: BoundedVec<T::AccountId, T::MaxAdmins>,
        pub access_controls: BoundedVec<AccessControl<T::AccountId>, T::MaxControls>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                admins: Default::default(),
                access_controls: Default::default(),
            }
        }
    }

    // The build of genesis for the pallet.
    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for admin in &self.admins {
                <Admins<T>>::insert(admin, ());
            }

            for access_control in &self.access_controls {
                match access_control.accounts.clone().try_into() {
                    Ok(bounded_accounts) => {
                        <AccessControls<T>>::insert::<
                            Action,
                            BoundedVec<T::AccountId, T::MaxAccountsPerAction>,
                        >(access_control.action.clone(), bounded_accounts);
                    }
                    Err(err) => {
                        log::error!("accounts probably hold more than maximum account numbers. Skipping adding accounts: {err:?}");
                    }
                };
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ActionCreated(Vec<u8>, Vec<u8>),
        ActionDeleted(Vec<u8>, Vec<u8>),
        AccessRevoked(T::AccountId, Vec<u8>, Vec<u8>),
        AccessGranted(T::AccountId, Vec<u8>, Vec<u8>),
        AdminAdded(T::AccountId),
        AdminRevoked(T::AccountId),
    }

    #[derive(PartialEq)]
    #[pallet::error]
    pub enum Error<T> {
        AccessDenied,
        ActionNotFound,
        UserNotFound,
        UserAlreadyExists,
        AdminNotFound,
        AdminAlreadyExists,
        ActionAlreadyExists,
        MaxAccountLimit,
        MaxAdminLimit,
        MaxControlLimit,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /**
            Create Access Control for a specific extrinsic on a pallet.
            The caller must have permissions in `access_control` action
        */
        #[pallet::call_index(0)]
        #[pallet::weight(10_000_000)]
        pub fn create_access_control(
            origin: OriginFor<T>,
            pallet_name: Vec<u8>,
            pallet_extrinsic: Vec<u8>,
        ) -> DispatchResult {
            let maybe_account = match T::AdminOrigin::ensure_origin(origin.clone()) {
                Ok(_) => {
                    log::info!("Root privileges recognized");
                    None
                }
                Err(_) => {
                    let signer = ensure_signed(origin.clone())?;

                    match Self::verify_execute_access(
                        &signer,
                        "AccessControl".as_bytes().to_vec(),
                        "create_access_control".as_bytes().to_vec(),
                    ) {
                        Ok(_) => {
                            log::info!("Successfully verified access");
                            Some(signer)
                        }
                        Err(_e) => {
                            return Err(Error::<T>::AccessDenied.into());
                        }
                    }
                }
            };

            // times 2, because each control consists of 2 actions
            if (AccessControls::<T>::iter().count() as u32) >= T::MaxControls::get() * 2 {
                return Err(Error::<T>::MaxControlLimit.into());
            }

            let execute_action = Action {
                pallet: pallet_name.clone(),
                extrinsic: pallet_extrinsic.clone(),
                permission: Permission::Execute,
            };

            if AccessControls::<T>::contains_key(execute_action.clone()) {
                return Err(Error::<T>::ActionAlreadyExists.into());
            }

            let manage_action = Action {
                pallet: pallet_name.clone(),
                extrinsic: pallet_extrinsic.clone(),
                permission: Permission::Manage,
            };

            if AccessControls::<T>::contains_key(manage_action.clone()) {
                return Err(Error::<T>::ActionAlreadyExists.into());
            }

            let accounts: BoundedVec<T::AccountId, T::MaxAccountsPerAction> = match maybe_account {
                Some(account) => vec![account]
                    .try_into()
                    .expect("1 element vec is always convertible"),
                None => Default::default(), // in case of root, we don't add any accounts
            };

            AccessControls::<T>::insert(execute_action, accounts.clone());
            AccessControls::<T>::insert(manage_action, accounts);

            Self::deposit_event(Event::ActionCreated(pallet_name, pallet_extrinsic));

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(10_000_000)]
        pub fn delete_access_control(
            origin: OriginFor<T>,
            pallet_name: Vec<u8>,
            pallet_extrinsic: Vec<u8>,
        ) -> DispatchResult {
            match T::AdminOrigin::ensure_origin(origin.clone()) {
                Ok(_) => {
                    log::info!("Root privileges recognized");
                    None
                }
                Err(_) => {
                    let signer = ensure_signed(origin.clone())?;

                    match Self::verify_manage_access(
                        &signer,
                        pallet_name.clone(),
                        pallet_extrinsic.clone(),
                    ) {
                        Ok(_) => {
                            log::info!("Successfully verified access");
                            Some(signer)
                        }
                        Err(_e) => {
                            return Err(Error::<T>::AccessDenied.into());
                        }
                    }
                }
            };

            let execute_action = Action {
                pallet: pallet_name.clone(),
                extrinsic: pallet_extrinsic.clone(),
                permission: Permission::Execute,
            };

            if !AccessControls::<T>::contains_key(execute_action.clone()) {
                return Err(Error::<T>::ActionNotFound.into());
            }

            let manage_action = Action {
                pallet: pallet_name.clone(),
                extrinsic: pallet_extrinsic.clone(),
                permission: Permission::Manage,
            };

            if !AccessControls::<T>::contains_key(manage_action.clone()) {
                return Err(Error::<T>::ActionNotFound.into());
            }

            AccessControls::<T>::remove(execute_action);
            AccessControls::<T>::remove(manage_action);

            Self::deposit_event(Event::ActionDeleted(pallet_name, pallet_extrinsic));

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(10_000_000)]
        pub fn grant_access(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            action: Action,
        ) -> DispatchResult {
            match T::AdminOrigin::ensure_origin(origin.clone()) {
                Ok(_) => {
                    log::info!("Root privileges recognized");
                }
                Err(_) => {
                    let signer = ensure_signed(origin)?;

                    match Self::verify_manage_access(
                        &signer,
                        action.pallet.clone(),
                        action.extrinsic.clone(),
                    ) {
                        Ok(_) => {
                            log::info!("Successfully verified access");
                        }
                        Err(_e) => {
                            return Err(Error::<T>::AccessDenied.into());
                        }
                    }
                }
            }

            match AccessControls::<T>::get(action.clone()) {
                Some(mut accounts) => {
                    if accounts.contains(&account_id) {
                        return Err(Error::<T>::UserAlreadyExists.into());
                    }
                    log::info!("Accounts: {:?}", accounts);
                    match accounts.try_push(account_id.clone()) {
                        Ok(_) => {}
                        Err(_) => {
                            log::error!("for action: {action:?}, max account limit has reached, cannot add new account");
                            return Err(Error::<T>::MaxAccountLimit.into());
                        }
                    };

                    AccessControls::<T>::insert(action.clone(), accounts);

                    Self::deposit_event(Event::AccessGranted(
                        account_id.clone(),
                        action.pallet.clone(),
                        action.extrinsic.clone(),
                    ));

                    Ok(())
                }
                None => return Err(Error::<T>::ActionNotFound.into()),
            }
        }

        #[pallet::call_index(3)]
        #[pallet::weight(10_000_000)]
        pub fn revoke_access(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            action: Action,
        ) -> DispatchResult {
            match T::AdminOrigin::ensure_origin(origin.clone()) {
                Ok(_) => {
                    log::info!("Root privileges recognized");
                }
                Err(_) => {
                    let signer = ensure_signed(origin)?;

                    match Self::verify_manage_access(
                        &signer,
                        action.pallet.clone(),
                        action.extrinsic.clone(),
                    ) {
                        Ok(_) => {
                            log::info!("Successfully verified access");
                        }
                        Err(_e) => {
                            return Err(Error::<T>::AccessDenied.into());
                        }
                    }
                }
            }

            match AccessControls::<T>::get(action.clone()) {
                Some(mut accounts) => {
                    if !accounts.contains(&account_id) {
                        return Err(Error::<T>::UserNotFound.into());
                    }
                    accounts.retain(|stored_account| stored_account != &account_id);
                    AccessControls::<T>::insert(action.clone(), accounts);

                    Self::deposit_event(Event::AccessRevoked(
                        account_id.clone(),
                        action.pallet.clone(),
                        action.extrinsic.clone(),
                    ));

                    Ok(())
                }
                None => Err(Error::<T>::ActionNotFound.into()),
            }
        }

        /// Add a new Super Admin.
        /// Admins have access to execute and manage all pallets.
        ///
        /// Only _root_ can add an Admin.
        #[pallet::call_index(4)]
        #[pallet::weight(10_000_000)]
        pub fn add_admin(origin: OriginFor<T>, account_id: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            if (<Admins<T>>::iter().count() as u32) >= T::MaxAdmins::get() {
                return Err(Error::<T>::MaxAdminLimit.into());
            }

            if <Admins<T>>::contains_key(&account_id) {
                return Err(Error::<T>::AdminAlreadyExists.into());
            }

            <Admins<T>>::insert(&account_id, ());
            Self::deposit_event(Event::AdminAdded(account_id));
            Ok(())
        }

        /// Revokes admin privileges
        ///
        /// Only _root_ can revoke an admin privilege
        #[pallet::call_index(5)]
        #[pallet::weight(10_000_000)]
        pub fn revoke_admin(origin: OriginFor<T>, account_id: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            if !<Admins<T>>::contains_key(&account_id) {
                return Err(Error::<T>::AdminNotFound.into());
            }

            <Admins<T>>::remove(&account_id);
            Self::deposit_event(Event::AdminRevoked(account_id));
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Verify that account can execute an extrinsic on a pallet.
    /// Access is denied when then a pallet and an extrinsic has a access_control,
    /// and the account does not have permission to execute.
    /// _root_ will bypass this check,
    /// people in the `execute` group and admins can pass this verification
    pub fn verify_execute_access(
        signer: &T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
    ) -> Result<(), Error<T>> {
        Self::verify_access(signer, pallet, extrinsic, Permission::Execute)
    }

    /// Verify the ability to manage the access to a pallets extrinsics.
    /// this is used for managing `execute` and `manage` privileges for a pallet
    /// _root_ will bypass this check,
    /// people in the `manage` group and admins can pass this verification
    pub fn verify_manage_access(
        signer: &T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
    ) -> Result<(), Error<T>> {
        Self::verify_access(signer, pallet, extrinsic, Permission::Manage)
    }

    fn verify_access(
        signer: &T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
        permission: Permission,
    ) -> Result<(), Error<T>> {
        // grant access to all admins
        if <Admins<T>>::contains_key(signer) {
            return Ok(());
        }

        let action = Action {
            pallet,
            extrinsic,
            permission,
        };

        match <AccessControls<T>>::get(action) {
            Some(accounts) => {
                if accounts.contains(signer) {
                    Ok(())
                } else {
                    Err(Error::<T>::AccessDenied)
                }
            }
            None => {
                // means this action is not yet created, no further checks to be applied
                Ok(())
            }
        }
    }
}

impl<T: Config> VerifyAccess<T::AccountId> for Pallet<T> {
    /// Expose the verify_execute_access to other pallets
    fn verify_execute_access(
        account_id: T::AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
    ) -> Result<(), TraitError> {
        match Self::verify_execute_access(&account_id, pallet, extrinsic) {
            Ok(()) => Ok(()),
            Err(_e) => Err(TraitError::AccessDenied),
        }
    }

    fn accessors(pallet: Vec<u8>, extrinsic: Vec<u8>) -> Option<Vec<T::AccountId>> {
        let key = Action {
            pallet,
            extrinsic,
            permission: Permission::Execute,
        };

        Self::access_controls(key).map(|bounded_vec| bounded_vec.into())
    }
}

/// The following section implements the `SignedExtension` trait
/// for the `Authorize` type.
/// `SignedExtension` is being used here to filter out the not authorized accounts
/// when they try to send extrinsics to the runtime.
/// Inside the `validate` extrinsic of the `SignedExtension` trait,
/// we check if the sender (origin) of the extrinsic has the execute permission or not.
/// The validation happens at the transaction queue level,
/// and the extrinsics are filtered out before they hit the pallet logic.

/// The `Authorize` struct.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct Authorize<T: Config + Send + Sync>(sp_std::marker::PhantomData<T>);

impl<T: Config + Send + Sync> Default for Authorize<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug impl for the `Authorize` struct.
impl<T: Config + Send + Sync> sp_std::fmt::Debug for Authorize<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "Authorize")
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        Ok(())
    }
}

impl<T: Config + Send + Sync> Authorize<T> {
    pub fn new() -> Self {
        Self(sp_std::marker::PhantomData)
    }
}

impl<T: Config + Send + Sync> SignedExtension for Authorize<T>
where
    T::RuntimeCall:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + GetCallMetadata,
{
    type AccountId = T::AccountId;
    type Call = T::RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();
    const IDENTIFIER: &'static str = "Authorize";

    fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
        Ok(())
    }

    /// Used to drop the transaction at the transaction pool level and prevents a transaction from being gossiped
    fn validate(
        &self,
        who: &Self::AccountId,
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        let call_metadata = call.get_call_metadata();
        if <Admins<T>>::contains_key(who) {
            return Ok(Default::default());
        }

        match <Pallet<T>>::verify_execute_access(
            who,
            call_metadata.pallet_name.as_bytes().to_vec(),
            call_metadata.function_name.as_bytes().to_vec(),
        ) {
            Ok(_) => Ok(Default::default()),
            Err(e) => {
                log::error!("{:?}! who: {:?}", e, who);
                Err(InvalidTransaction::Call.into())
            }
        }
    }

    /// Use to hook in before the transaction runs
    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        match self.validate(who, call, info, len) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
