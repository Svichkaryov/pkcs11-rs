use crate::{
    error::{CryptokiRetVal, Result},
    module::{general_purpose::*, session::*, types::*},
};

impl Session {
    /// Mixes additional seed material into the token's random number generator.
    pub fn seed_random(&self, seed: &[Byte]) -> Result<()> {
        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_SeedRandom,
            self.handle(),
            seed.as_ptr() as CK_BYTE_PTR,
            seed.len() as Ulong
        ))
        .into_result()
    }

    /// Generates random or pseudo-random data of the given length in bytes.
    pub fn generate_random(&self, random_len: Ulong) -> Result<Vec<Byte>> {
        let mut random_data: Vec<Byte> = vec![0; random_len as usize];

        CryptokiRetVal::from(invoke_pkcs11!(
            self.module(),
            C_GenerateRandom,
            self.handle(),
            random_data.as_mut_ptr() as CK_BYTE_PTR,
            random_len
        ))
        .into_result()?;

        Ok(random_data)
    }
}
