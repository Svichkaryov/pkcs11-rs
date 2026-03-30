use libloading;
use std::{path::Path, sync::Arc};

use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{ck_util, types::*},
};

macro_rules! invoke_pkcs11 {
    ($p11_mod:expr, $func_name:ident, $($params:expr),*) => {
        // Unwrap always return Some because there is a check in `check_ck_functional_list_valid`
        // that each cryptoki function should point to a function stub.
        $p11_mod.impl_.function_list.$func_name.unwrap()($($params),*)
    };
}

pub(crate) use invoke_pkcs11;

#[derive(Debug)]
pub(crate) struct Pkcs11ModuleImpl {
    _library: libloading::Library,
    pub(crate) function_list: CK_FUNCTION_LIST,
}

impl Pkcs11ModuleImpl {
    fn finalize(&self) -> Result<()> {
        CryptokiRetVal::from(self.function_list.C_Finalize.unwrap()(std::ptr::null_mut()))
            .into_result()
    }
}

impl Drop for Pkcs11ModuleImpl {
    fn drop(&mut self) {
        if let Err(e) = self.finalize() {
            println!("Failed to finalize Pkcs11ModuleImpl: {}", e);
        }
    }
}

// TODO: add typesafe pattern
#[derive(Debug, Clone)]
pub struct Pkcs11Module {
    pub(crate) impl_: Arc<Pkcs11ModuleImpl>,
    initialized: bool,
}

impl Pkcs11Module {
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let lib = libloading::Library::new(filename.as_ref())
                .map_err(Error::LibraryLoading)?;
            let func_list_sym: libloading::Symbol<C_GetFunctionList> =
                lib.get(b"C_GetFunctionList")?;
            let mut ck_func_list =
                std::mem::MaybeUninit::<CK_FUNCTION_LIST_PTR>::uninit();

            CryptokiRetVal::from(func_list_sym(ck_func_list.as_mut_ptr()))
                .into_result()?;

            let ck_func_list_ptr: *mut CK_FUNCTION_LIST = ck_func_list.assume_init();

            ck_util::check_ck_functional_list_valid(ck_func_list_ptr)?;

            Ok(Pkcs11Module {
                impl_: Arc::new(Pkcs11ModuleImpl {
                    _library: lib,
                    function_list: *ck_func_list_ptr,
                }),
                initialized: false,
            })
        }
    }

    /// Initializes the Cryptoki library.
    pub fn initialize(&mut self, init_args: InitializeArgs) -> Result<()> {
        if self.is_initialized() {
            return Err(Error::AlreadyInitialized);
        }

        let mut ck_init_args = CK_C_INITIALIZE_ARGS::from(init_args);
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_Initialize,
            ck_init_args.as_mut_ptr() as CK_VOID_PTR
        ))
        .into_result()
        .map(|_| {
            self.initialized = true;
        })
    }

    pub fn initialized(&self) -> Result<()> {
        if !self.initialized {
            Err(Error::NotInitialized)
        } else {
            Ok(())
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Stub
    pub fn finalize(self) {}

    /// Returns general information about Cryptoki.
    pub fn get_info(&self) -> Result<Info> {
        self.initialized()?;

        let mut info = CK_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(self, C_GetInfo, &mut info)).into_result()?;

        Info::try_from(info)
    }

    /// Obtains the Cryptoki library's list of function pointers.
    pub fn get_function_list(&self) -> Result<FunctionList> {
        Ok(self.impl_.function_list)
    }
}

// impl Drop for Pkcs11Module {
//     fn drop(&mut self) {
//         println!("Drop from Pkcs11Module");
//         // There is no `initialized` flag reset as it is not logically required
//         // after library finalization.
//     }
// }
