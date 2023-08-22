use crate::Vec;

pub enum TraitError {
    AccessDenied,
}

pub trait VerifyAccess<AccountId> {
    /** Verify that account can execute a function on a pallet.
     All Pallet functions works as normal when it does not have an access_control created for it.
     Access is denied when then pallet and function has an access_control, and the account does not have permission to execute.
     Additionally when using the trait, if the pallet extrinsic is not found access will be denied.
    */
    fn verify_execute_access(
        account_id: AccountId,
        pallet: Vec<u8>,
        extrinsic: Vec<u8>,
    ) -> Result<(), TraitError>;

    fn accessors(pallet: Vec<u8>, extrinsic: Vec<u8>) -> Option<Vec<AccountId>>;
}
