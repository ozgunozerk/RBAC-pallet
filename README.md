# Substrate Access Control Pallet

### Including a working example with [substrate-node-rbac](https://github.com/ozgunozerk/substrate-node-rbac)

Forked from [access-control](https://github.com/WunderbarNetwork/access-control)
Which is another fork from [substrate-rbac](https://github.com/gautamdhameja/substrate-rbac)

A [Substrate](https://github.com/paritytech/substrate) pallet implementing access controls and permissions for Substrate extrinsic calls.

The filtering of incoming extrinsics and their sender accounts is done at the transaction queue validation layer, using the `SignedExtension` trait.
Extrinsics operate with substrates default behavior if they do not have access controls enabled.

Introduce the `VerifyAccess` type into the config of your custom pallets and call the `verify_execution_access` function to ensure a specific extrinsic has access controls by default.

## Usage

1. Add the module's dependency in the `Cargo.toml` of your `runtime` directory. Make sure to enter the correct path or git url of the pallet as per your setup.

```toml
access-control = { version = "0.1.0", default-features = false, git = "https://github.com/ozgunozerk/RBAC-pallet" }
```

2. again, in `cargo.toml`, add this entry to the `std` feature:
```toml
"access-control/std",
```

3. Declare the pallet in your `runtime/src/lib.rs`.

```rust
// runtime/src/lib.rs
pub use access_control;
```

4. add `access_control::Config` implementation for `Runtime`
```rust
impl access_control::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type AdminOrigin = EnsureRoot<AccountId>;
}
```

5. if you have `create_transaction`, do the following (I don't have this)
```rust
fn create_transaction(...) -> Option<(...)> {
    // ...

    let extra = (
        // ...
        access_control::Authorize::<Runtime>::new(),
    );
}
```

6. Add access_control to the runtime
```rust
construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        // ...
        AccessControl: access_control,
        // ...
    }
);
```
7. Optional: Add the module's `Authorize` type in the `SignedExtra` checklist.
```rust
pub type SignedExtra = (
    // ...
   access_control::Authorize<Runtime>,
);

//...
```

8. Add a genesis configuration for the module in the `node/src/chain_spec.rs` file.

```rust
/// node/src/chain_spec.rs

// Import access_control and AccessControlConfig from the runtime
use node_template_runtime::{ // replace it with your node name
    // ...
    access_control, AccessControlConfig
}

// ...
// inside this function, add the below
fn testnet_genesis(...) -> GenesisConfig {
    let authorized_accounts = vec![get_account_id_from_seed::<sr25519::Public>("Alice")];

	// Create initial access controls including the AccessControl Pallet
	let actions = vec![
		// Create both Execute and Manage controls for the AccessControl Pallets
		// `create_access_control` extrinsic.
		access_control::Action {
			pallet: "AccessControl".as_bytes().to_vec(),
			extrinsic: "create_access_control".as_bytes().to_vec(),
			permission: access_control::Permission::Execute,
		},
		access_control::Action {
			pallet: "AccessControl".as_bytes().to_vec(),
			extrinsic: "create_access_control".as_bytes().to_vec(),
			permission: access_control::Permission::Manage,
		},
		// ... additional Actions ...
	];

	// Create the AccessControl struct for access controls and accounts who can action.
	let access_controls: Vec<access_control::AccessControl<AccountId>> = actions
		.iter()
		.map(|action| access_control::AccessControl {
			action: action.clone(),
			accounts: authorized_accounts.clone(),
		})
		.collect::<Vec<_>>();

    // ...

    GenesisConfig {
        /// ...
        access_control: AccessControlConfig { admins: authorized_accounts.clone() , access_controls }
    }
}
```

### Access Control for custom pallets

1. add this to the `cargo.toml` of the pallet
```toml
access-control = { version = "0.1.0", default-features = false, git = "https://github.com/ozgunozerk/RBAC-pallet" }
```

2. add this entry to the `std` feature:
```toml
"access-control/std",
```


3. in `lib.rs` of the pallet: import `access-control`s trait inside `pub mod pallet`
```rust
pub mod pallet {
    use access_control::traits::VerifyAccess;
// ...
```

4. add the necessary type for loose coupling
```rust
#[pallet::config]
pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
    // ...

    /// Add VerifyAccess trait to the pallet.
    type VerifyAccess: VerifyAccess<Self::AccountId>;
}
```

5. now we can use the `verify_execute_access` in business logic (below is an example)
```rust
#[pallet::call_index(0)]
		#[pallet::weight(10_000 + T::DbWeight::get().writes(1).ref_time())]
		pub fn do_something(origin: OriginFor<T>, something: u32) -> DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://docs.substrate.io/main-docs/build/origins/
			let who = ensure_signed(origin)?;

			match T::VerifyAccess::verify_execute_access(
				&who,
				"MyCustomPallet".as_bytes().to_vec(),
				"do_something".as_bytes().to_vec(),
			) {
				Ok(_) => {
					// Update storage.
					<Something<T>>::put(something);

					// Emit an event.
					Self::deposit_event(Event::SomethingStored { something, who });
					// Return a successful DispatchResultWithPostInfo
					Ok(())
				},
				Err(_) => return Err(frame_support::error::BadOrigin.into()),
			}
		}
```

6. we have to update `Config` implementation for `Runtime` in `runtime/src/lib.rs` as well:
```rust
/// Configure the pallet-template in pallets/template.
impl pallet_template::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;

	// add this line
	type VerifyAccess = AccessControl;
}
```

It is also encouraged to have a `rust-toolchain.toml` file for your node to prevent conflicts between rust versions.

Build with:
```bash
cargo build --release
```

For a working example, check [substrate-node-rbac](https://github.com/ozgunozerk/substrate-node-rbac)

## Disclaimer

This code not audited and reviewed for production use cases. You can expect bugs and security vulnerabilities. Do not use it as-is in real applications.
