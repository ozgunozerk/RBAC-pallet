use crate::{self as access_control};
use frame_support::traits::{ConstU16, ConstU64, GenesisBuild};
use frame_support::BoundedVec;
use frame_system as system;
use sp_core::{bounded_vec, sr25519::Signature, Get, Pair, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
};
use sp_std::convert::{TryFrom, TryInto};
use system::EnsureRoot;
use test_context::TestContext;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

pub struct MaxAdmins;
impl Get<u32> for MaxAdmins {
    fn get() -> u32 {
        2
    }
}

pub struct MaxControls;
impl Get<u32> for MaxControls {
    fn get() -> u32 {
        4
    }
}

pub struct MaxAccounts;
impl Get<u32> for MaxAccounts {
    fn get() -> u32 {
        4
    }
}

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        AccessControl: access_control,
    }
);

impl system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = sp_core::sr25519::Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl access_control::Config for Test {
    type MaxAdmins = MaxAdmins;
    type MaxControls = MaxControls;
    type MaxAccountsPerAction = MaxAccounts;
    type RuntimeEvent = RuntimeEvent;
    type AdminOrigin = EnsureRoot<AccountId>;
}

pub struct WithAccessControlContext {
    pub admins: BoundedVec<AccountId, MaxAdmins>,
    pub access_controls: BoundedVec<access_control::AccessControl<AccountId>, MaxControls>,
}

impl TestContext for WithAccessControlContext {
    fn setup() -> Self {
        // Create a admin account that is not root.
        let admin_account = new_account();

        // Seed AccessControls for executing the extrinsic `create_access_control`.
        let execute_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: extrinsic_name(),
            permission: access_control::Permission::Execute,
        };

        // Seed AccessControls for managing the extrinsic `create_access_control`.
        let manage_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: extrinsic_name(),
            permission: access_control::Permission::Manage,
        };

        WithAccessControlContext {
            admins: bounded_vec![admin_account],
            access_controls: bounded_vec![
                access_control::AccessControl {
                    action: execute_action,
                    accounts: vec![],
                },
                access_control::AccessControl {
                    action: manage_action,
                    accounts: vec![],
                },
            ],
        }
    }
}

impl WithAccessControlContext {
    pub fn admin_signer(&self) -> RuntimeOrigin {
        RuntimeOrigin::signed(*self.admins.first().unwrap())
    }

    pub fn admin_id(&self) -> AccountId {
        *self.admins.first().unwrap()
    }
}

pub fn pallet_name() -> Vec<u8> {
    "AccessControl".as_bytes().to_vec()
}

pub fn extrinsic_name() -> Vec<u8> {
    "create_access_control".as_bytes().to_vec()
}

pub fn fake_extrinsic() -> Vec<u8> {
    "fake_extrinsic".as_bytes().to_vec()
}

pub fn max_account_limit() -> u32 {
    MaxAccounts::get()
}

pub fn max_admin_limit() -> u32 {
    MaxAdmins::get()
}

pub fn max_control_limit() -> u32 {
    MaxControls::get()
}

pub fn new_account() -> sp_core::sr25519::Public {
    let key_pair = sp_core::sr25519::Pair::generate_with_phrase(None);
    key_pair.0.public()
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext(access_controls_ctx: &WithAccessControlContext) -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    let genesis = access_control::GenesisConfig::<Test> {
        admins: access_controls_ctx.admins.clone(),
        access_controls: access_controls_ctx.access_controls.clone(),
    };
    genesis.assimilate_storage(&mut t).unwrap();
    t.into()
}
