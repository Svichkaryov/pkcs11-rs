use super::general::*;

pub type FunctionList = CK_FUNCTION_LIST;

// CK_C_INITIALIZE_ARGS

/// Structure containing information on how the library should deal with
/// multi-threaded access.
#[derive(Debug, Copy, Clone)]
pub enum InitializeArgs {
    /// The application won't be accessing the Cryptoki library from multiple
    /// threads simultaneously.
    Null,

    /// The application will be performing multi-threaded Cryptoki access, and
    /// the library needs to use the native operating system primitives
    /// to ensure safe multi-threaded access. If the library is unable
    /// to do this, C_Initialize should return with the value CKR_CANT_LOCK.
    OsLocking,
}

impl From<InitializeArgs> for CK_C_INITIALIZE_ARGS {
    fn from(init_args: InitializeArgs) -> Self {
        let mut ck_c_init_arg = CK_C_INITIALIZE_ARGS::default();
        if let InitializeArgs::OsLocking = init_args {
            ck_c_init_arg.flags = CKF_OS_LOCKING_OK;
        }
        ck_c_init_arg
    }
}
