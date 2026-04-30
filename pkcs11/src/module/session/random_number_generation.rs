use crate::{
    error::{CryptokiRetVal, Error, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    /// Mixes additional seed material into the token's random number generator.
    pub fn seed_random(&self, seed: &[u8]) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SeedRandom,
            self.handle().into(),
            seed.as_ptr() as CK_BYTE_PTR,
            seed.len().try_into().map_err(|_| Error::InvalidInput)?
        ))
        .into_result()
    }

    /// Generates random or pseudo-random data of the given length in bytes.
    pub fn generate_random(&self, random_len: u32) -> Result<Vec<u8>> {
        let mut random_data: Vec<u8> = vec![0; random_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GenerateRandom,
            self.handle().into(),
            random_data.as_mut_ptr() as CK_BYTE_PTR,
            random_len.into()
        ))
        .into_result()?;

        Ok(random_data)
    }
}
