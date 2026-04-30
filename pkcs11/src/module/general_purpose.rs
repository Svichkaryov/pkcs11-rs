use {
    libloading,
    std::{path::Path, sync::Arc},
};

use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{ck_util, types::*},
};

macro_rules! invoke_pkcs11 {
    ($p11_mod:expr, $func_name:ident, $($params:expr),*) => {
        // Unwrap always return Some because there is a check in `check_ck_functional_list_valid`
        // that each cryptoki function should point to a function stub.
        $p11_mod.get_function_list().$func_name.unwrap()($($params),*)
    };
}

pub(crate) use invoke_pkcs11;

#[derive(Debug)]
pub(crate) struct Pkcs11ModuleImpl {
    _library: libloading::Library,
    function_list: CK_FUNCTION_LIST,
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
            eprintln!("Failed to finalize Pkcs11ModuleImpl: {}", e);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Uninitialized;

#[derive(Debug, Clone)]
pub struct Initialized;

mod private {
    pub trait Sealed {}
    impl Sealed for super::Uninitialized {}
    impl Sealed for super::Initialized {}
}
pub trait ModuleState: private::Sealed {}
impl ModuleState for Uninitialized {}
impl ModuleState for Initialized {}

#[derive(Debug, Clone)]
pub struct Pkcs11Module<S: ModuleState> {
    pub(crate) impl_: Arc<Pkcs11ModuleImpl>,
    _phantom: std::marker::PhantomData<S>,
}

impl<S: ModuleState> Pkcs11Module<S> {
    /// Obtains the Cryptoki library's list of function pointers.
    pub(crate) fn get_function_list(&self) -> CK_FUNCTION_LIST {
        self.impl_.function_list
    }
}

impl Pkcs11Module<Uninitialized> {
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

            Ok(Self {
                impl_: Arc::new(Pkcs11ModuleImpl {
                    _library: lib,
                    function_list: *ck_func_list_ptr,
                }),
                _phantom: std::marker::PhantomData,
            })
        }
    }

    /// Initializes the Cryptoki library.
    pub fn initialize(
        self,
        init_args: InitializeArgs,
    ) -> Result<Pkcs11Module<Initialized>> {
        let mut ck_init_args = CK_C_INITIALIZE_ARGS::from(init_args);
        CryptokiRetVal::from(invoke_pkcs11!(
            self,
            C_Initialize,
            &mut ck_init_args as *mut CK_C_INITIALIZE_ARGS as CK_VOID_PTR
        ))
        .into_result()?;

        Ok(Pkcs11Module {
            impl_: self.impl_,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl Pkcs11Module<Initialized> {
    /// Stub
    pub fn finalize(self) {}

    /// Returns general information about Cryptoki.
    pub fn get_info(&self) -> Result<Info> {
        let mut info = CK_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(self, C_GetInfo, &mut info)).into_result()?;

        Info::try_from(info)
    }
}

// impl Drop for Pkcs11Module {
//     fn drop(&mut self) {
//         println!("Drop from Pkcs11Module");
//         // There is no `initialized` flag reset as it is not logically required
//         // after library finalization.
//     }
// }
