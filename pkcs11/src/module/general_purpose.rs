use {
    libloading,
    std::{path::Path, sync::Arc},
};

use pkcs11_sys::*;

use crate::{
    ck_util,
    error::{CryptokiRetVal, Error, Result},
    types::{Info, InitializeArgs},
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

/// The library module state before Cryptoki has been initialized.
#[derive(Debug, Clone)]
pub struct Uninitialized;

/// The library module state after Cryptoki has been initialized.
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

/// A handle to a loaded PKCS#11 library.
///
/// The module uses the typestate to represent whether the library has been
/// initialized. A `Pkcs11Module<Uninitialized>` can be created from a shared
/// library path and is then transitioned into `Pkcs11Module<Initialized>`
/// by calling [`initialize`].
///
/// The underlying library is finalized automatically when the last clone of
/// the module handle is dropped.
///
/// # Example
///
/// ```no_run
/// use pkcs11::module::Pkcs11Module;
/// use pkcs11::types::InitializeArgs;
///
/// fn main() -> pkcs11::error::Result<()> {
///     let pkcs11 = Pkcs11Module::new("/usr/lib/libpkcs11.so")?;
///     let pkcs11 = pkcs11.initialize(InitializeArgs::OsLocking)?;
///     
///     let slots = pkcs11.get_all_slots()?;
///     for slot in slots {
///         println!("slot: {}", slot);
///     }
///
///     Ok(())
/// }
/// ```
///
/// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
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
    /// Load a PKCS#11 library from the given `path`.
    ///
    /// This returns an uninitialized module and does not perform Cryptoki
    /// initialization. The library is not ready for token or slot
    /// operations until it is transitioned with [`initialize`].
    ///
    /// [`initialize`]: crate::doc_links::Pkcs11Module::initialize
    pub fn new<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let lib =
                libloading::Library::new(path.as_ref()).map_err(Error::LibraryLoading)?;
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

    /// Initializes the loaded Cryptoki library.
    ///
    /// Return initialized module that supports all slot and token
    /// operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pkcs11::module::Pkcs11Module;
    /// use pkcs11::types::InitializeArgs;
    ///
    /// # fn main() -> pkcs11::error::Result<()> {
    /// let pkcs11 = Pkcs11Module::new("/usr/lib/libpkcs11.so")?;
    /// let pkcs11 = pkcs11.initialize(InitializeArgs::OsLocking)?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// Stub function. The library is automatically finalized when the module
    /// handle is dropped.
    #[allow(dead_code)]
    pub fn finalize(self) {}

    /// Returns general information about Cryptoki.
    pub fn get_info(&self) -> Result<Info> {
        let mut info = CK_INFO::default();
        CryptokiRetVal::from(invoke_pkcs11!(self, C_GetInfo, &mut info)).into_result()?;

        Info::try_from(info)
    }
}
