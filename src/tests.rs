use crate::{self as access_control};
use crate::{
    mock::{WithAccessControlContext, *},
    Error, Permission,
};
use frame_support::error::BadOrigin;
use frame_support::{assert_noop, assert_ok};
use sp_core::bounded_vec;
use std::convert::TryInto;
use test_context::test_context;

#[test_context(WithAccessControlContext)]
#[test]
fn authorized_execution_of_an_extrinsic(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let expected_execute_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: fake_extrinsic(),
            permission: Permission::Execute,
        };

        let expected_manage_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: fake_extrinsic(),
            permission: Permission::Manage,
        };

        assert_ok!(AccessControl::create_access_control(
            ctx.admin_signer(),
            pallet_name(),
            fake_extrinsic(),
        ));

        assert_eq!(
            AccessControl::access_controls(expected_execute_action),
            Some(bounded_vec![ctx.admin_id()])
        );

        assert_eq!(
            AccessControl::access_controls(expected_manage_action),
            Some(bounded_vec![ctx.admin_id()])
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn deny_execution_of_an_extrinsic(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let another_account = new_account();
        let signer = RuntimeOrigin::signed(another_account);

        assert_noop!(
            AccessControl::create_access_control(signer, pallet_name(), fake_extrinsic(),),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn admin_override_create_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let expected_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: fake_extrinsic(),
            permission: Permission::Execute,
        };

        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::root(),
            expected_action.pallet.clone(),
            expected_action.extrinsic.clone(),
        ));

        assert_eq!(
            AccessControl::access_controls(expected_action),
            Some(bounded_vec![])
        )
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn delete_action(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = new_account();
        let action = ctx.access_controls.first().unwrap().action.clone();

        let new_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: fake_extrinsic(),
            permission: access_control::Permission::Execute,
        };

        // Add the new account to the admins who can create access controls
        assert_ok!(AccessControl::grant_access(
            ctx.admin_signer(),
            account_to_add,
            action.clone()
        ));

        // ensure that the new account is now able to create access controls
        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::signed(account_to_add),
            new_action.pallet.clone(),
            new_action.extrinsic.clone(),
        ));

        assert_eq!(
            AccessControl::access_controls(new_action.clone()),
            Some(bounded_vec![account_to_add])
        );

        // creator of the action should be able to delete the action itself
        assert_ok!(AccessControl::delete_access_control(
            RuntimeOrigin::signed(account_to_add),
            new_action.pallet.clone(),
            new_action.extrinsic.clone(),
        ));

        assert_eq!(AccessControl::access_controls(new_action), None);
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn delete_action_unauthorized(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = new_account();
        let unauthorized_signer = RuntimeOrigin::signed(new_account());
        let action = ctx.access_controls.first().unwrap().action.clone();

        let new_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: fake_extrinsic(),
            permission: access_control::Permission::Execute,
        };

        // Add the new account to the admins who can create access controls
        assert_ok!(AccessControl::grant_access(
            ctx.admin_signer(),
            account_to_add,
            action.clone()
        ));

        // ensure that the new account is now able to create access controls
        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::signed(account_to_add),
            new_action.pallet.clone(),
            new_action.extrinsic.clone(),
        ));

        assert_eq!(
            AccessControl::access_controls(new_action.clone()),
            Some(bounded_vec![account_to_add])
        );

        // without necessary privileges, one should not be able to delete the action
        assert_noop!(
            AccessControl::delete_access_control(
                unauthorized_signer,
                new_action.pallet.clone(),
                new_action.extrinsic.clone(),
            ),
            Error::<Test>::AccessDenied
        );

        // action should be still intact
        assert_eq!(
            AccessControl::access_controls(new_action),
            Some(bounded_vec![account_to_add])
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn assign_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = new_account();
        let unauthorized_signer = RuntimeOrigin::signed(account_to_add);
        let action = ctx.access_controls.first().unwrap().action.clone();

        let new_action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: fake_extrinsic(),
            permission: access_control::Permission::Execute,
        };

        // The new Account is denied access
        assert_noop!(
            AccessControl::create_access_control(
                unauthorized_signer,
                new_action.pallet.clone(),
                new_action.extrinsic.clone(),
            ),
            Error::<Test>::AccessDenied
        );

        // Add the new account to the admins who can create access controls
        assert_ok!(AccessControl::grant_access(
            ctx.admin_signer(),
            account_to_add,
            action.clone()
        ));

        assert!(AccessControl::access_controls(action.clone())
            .unwrap()
            .contains(&account_to_add));

        // ensure that the new account is now able to create access controls
        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::signed(account_to_add),
            new_action.pallet.clone(),
            new_action.extrinsic.clone(),
        ));

        assert_eq!(
            AccessControl::access_controls(new_action.clone()),
            Some(bounded_vec![account_to_add])
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn admin_override_assign_access_control(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = new_account();
        let action = ctx.access_controls.first().unwrap().action.clone();

        assert_ok!(AccessControl::grant_access(
            RuntimeOrigin::root(),
            account_to_add,
            action.clone()
        ));

        assert!(AccessControl::access_controls(action.clone())
            .unwrap()
            .contains(&account_to_add));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn revoke_access_for_an_account(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let manager_account = new_account();
        let account_to_add_then_remove = new_account();

        let action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: extrinsic_name(),
            permission: access_control::Permission::Manage,
        };

        assert_ok!(AccessControl::grant_access(
            ctx.admin_signer(),
            manager_account,
            action.clone()
        ));

        assert_ok!(AccessControl::grant_access(
            ctx.admin_signer(),
            account_to_add_then_remove,
            action.clone()
        ));

        assert_ok!(AccessControl::revoke_access(
            RuntimeOrigin::signed(manager_account),
            account_to_add_then_remove,
            action.clone()
        ));

        assert_noop!(
            AccessControl::revoke_access(
                RuntimeOrigin::signed(account_to_add_then_remove),
                manager_account,
                action.clone()
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn sudo_override_revoke_access(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add_then_remove = new_account();

        let action = access_control::Action {
            pallet: pallet_name(),
            extrinsic: extrinsic_name(),
            permission: access_control::Permission::Execute,
        };

        assert_ok!(AccessControl::grant_access(
            ctx.admin_signer(),
            account_to_add_then_remove,
            action.clone()
        ));

        assert_ok!(AccessControl::create_access_control(
            RuntimeOrigin::signed(account_to_add_then_remove),
            pallet_name(),
            fake_extrinsic(),
        ));

        assert_ok!(AccessControl::revoke_access(
            ctx.admin_signer(),
            account_to_add_then_remove,
            action.clone()
        ));

        assert!(!AccessControl::access_controls(action.clone())
            .unwrap()
            .contains(&account_to_add_then_remove));

        assert_noop!(
            AccessControl::create_access_control(
                RuntimeOrigin::signed(account_to_add_then_remove),
                pallet_name(),
                fake_extrinsic(),
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn add_admin(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = new_account();

        assert_ok!(AccessControl::add_admin(
            RuntimeOrigin::root(),
            account_to_add
        ));

        assert_eq!(AccessControl::admins(account_to_add), Some(()));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn add_admin_is_root_only(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_add = new_account();

        assert_noop!(
            AccessControl::add_admin(ctx.admin_signer(), account_to_add),
            BadOrigin
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn revoke_admin(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().unwrap();

        assert_ok!(AccessControl::revoke_admin(
            RuntimeOrigin::root(),
            *account_to_remove
        ));

        assert_eq!(AccessControl::admins(account_to_remove), None)
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn revoke_admin_is_root_only(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let account_to_remove = ctx.admins.first().unwrap();

        assert_noop!(
            AccessControl::revoke_admin(ctx.admin_signer(), *account_to_remove),
            BadOrigin
        );
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn max_account_per_action_count(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let action = ctx.access_controls.first().unwrap().action.clone();

        // Helper function to attempt to grant access to a new account
        let try_grant_access = |count| {
            let account_to_add = new_account();

            // Attempt to grant access
            let result =
                AccessControl::grant_access(ctx.admin_signer(), account_to_add, action.clone());

            let accounts_with_access = AccessControl::access_controls(action.clone()).unwrap();

            // recall, we assign an account to the action at genesis, so there is already an account here
            if (count + 1) <= max_account_limit() {
                assert_ok!(result);
                assert!(accounts_with_access.contains(&account_to_add));
                true
            } else {
                assert_noop!(result, Error::<Test>::MaxAccountLimit);
                assert!(!accounts_with_access.contains(&account_to_add));
                false
            }
        };

        // Try to add accounts up to the maximum limit
        for i in 1..max_account_limit() {
            // for limit, it is human counting, start from 1 instead of 0
            assert!(try_grant_access(i));
        }

        // Try to add one more account, expecting failure
        assert!(!try_grant_access(max_account_limit()));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn max_admin_count(ctx: &mut WithAccessControlContext) {
    new_test_ext(ctx).execute_with(|| {
        let try_add_admin = |count| {
            let account_to_add = new_account();

            let result = AccessControl::add_admin(RuntimeOrigin::root(), account_to_add);

            // recall, we assign an admin at genesis
            if (count + 1) <= max_admin_limit() {
                assert_ok!(result);
                assert_eq!(AccessControl::admins(account_to_add), Some(()));
                true
            } else {
                assert_noop!(result, Error::<Test>::MaxAdminLimit);
                assert_eq!(AccessControl::admins(account_to_add), None);
                false
            }
        };

        // Try to add admins up to the maximum limit
        for i in 1..max_admin_limit() {
            // for limit, it is human counting, start from 1 instead of 0
            assert!(try_add_admin(i));
        }

        // Try to add one more admin, expecting failure
        assert!(!try_add_admin(max_admin_limit()));
    });
}

#[test_context(WithAccessControlContext)]
#[test]
fn max_control_count(ctx: &mut WithAccessControlContext) {
    fn pallet_name_generator(count: u32) -> Vec<u8> {
        (count.to_string() + "AccessControl").as_bytes().to_vec()
    }
    new_test_ext(ctx).execute_with(|| {
        let try_add_control = |count| {
            let result = AccessControl::create_access_control(
                RuntimeOrigin::root(),
                pallet_name_generator(count),
                extrinsic_name(),
            );

            // recall, we assign a control at genesis
            if (count + 1) <= max_control_limit() {
                assert_ok!(result);
                true
            } else {
                assert_noop!(result, Error::<Test>::MaxControlLimit);
                false
            }
        };

        // Try to add controls up to the maximum limit
        for i in 1..max_control_limit() {
            // for limit, it is human counting, start from 1 instead of 0
            assert!(try_add_control(i));
        }

        // Try to add one more control, expecting failure
        assert!(!try_add_control(max_control_limit() + 1));
    });
}
