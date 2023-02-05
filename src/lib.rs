use rand::{rngs::StdRng, SeedableRng, RngCore};
use sha3::{Digest, Sha3_256};

#[derive(Debug)]
pub struct LamportSignature {
    secret: Key,
    pub public: Key
} 

pub type Key = ([[u8; 32]; 256], [[u8; 32]; 256]);
pub type Signature = [[u8; 32]; 256] ;

impl LamportSignature {
    pub fn generate_key(seed: &str) -> Self {
        // generate random secret key based on seed
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        let seed_bytes: [u8; 32] = hasher.finalize().into();
        let mut rand : StdRng = StdRng::from_seed(seed_bytes);
        let mut secret =  ([[0; 32]; 256], [[0; 32]; 256]);
        for secret0 in secret.0.as_mut() {
            rand.fill_bytes(secret0);
        }
        for secret1 in secret.1.as_mut() {
            rand.fill_bytes(secret1);
        }

        // generate public key as hash for every block of secret key(256bit)
        let mut public = ([[0; 32]; 256], [[0; 32]; 256]);

        for i in 0..256 {
            let secret0 = secret.0[i];
            let mut hasher = Sha3_256::new();
            hasher.update(secret0);
            let result0: [u8; 32] = hasher.finalize().into();
            public.0[i] = result0;
        }

        for i in 0..256 {
            let secret1 = secret.1[i];
            let mut hasher = Sha3_256::new();
            hasher.update(secret1);
            let result0: [u8; 32] = hasher.finalize().into();
            public.1[i] = result0;
        }

        LamportSignature {secret, public}
    }

    pub fn sign(&self, message: &str) ->Signature{
        // hash message
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        // pick private key to reveal based on bits of message
        let mut signature = [[0u8;32]; 256];
        let mut place = 0;
        for byte in hash {
            let mut copy = byte.clone();
            for _i in 0..8 {
                if copy & 0x01 == 0x01 {
                    signature[place] = self.secret.1[place]
                } else {
                    signature[place] = self.secret.0[place]
                }
                copy = copy >> 1;
                place = place+1;
            }
        }

        signature
    }
    pub fn verify(publickey: Key, message: &str, signature: Signature) -> bool{
          // hash message
          let mut hasher = Sha3_256::new();
          hasher.update(message);
          let hash: [u8; 32] = hasher.finalize().into();

          // verify by hashing every block of signature
          let mut place = 0;
          for byte in hash {
            let mut copy = byte.clone();
            for _i in 0..8 {
                let mut hasher = Sha3_256::new();
                hasher.update(signature[place]);
                let result: [u8; 32] = hasher.finalize().into();
                if copy & 0x01 == 0x01 {
                    if result != publickey.1[place] {
                        return false
                    }
                } else {
                    if result != publickey.0[place] {
                        return false;
                    }
                }
                copy = copy >> 1;
                place = place+1;
            }
        }
  
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::LamportSignature;
    use super::*;

    #[test]
    #[ignore = "test of 'rand' library"]
    fn rng() {
        let seed = [9; 32];
        let mut rand : StdRng = StdRng::from_seed(seed);
        // assert_ne!(rand.next_u32(), rand.next_u32());
        let mut buf1 = [0u8; 32];
        rand.fill_bytes(&mut buf1);
        let mut buf2 = [0u8; 32];
        rand.fill_bytes(&mut buf2);
        for i in 0..32 {
            assert_ne!(buf1[i], buf2[i]);
        }
    }

    #[test]
    fn generate_ok() {
        let seed = "[9;32]";
        let signature = LamportSignature::generate_key(seed);

        for i in 0..255 {
            assert_ne!(signature.public.0[i], signature.public.0[i+1]);
            assert_ne!(signature.public.1[i], signature.public.1[i+1]);
            assert_ne!(signature.public.0[i], signature.public.1[i]);
        }    
    }

    #[test]
    fn generate_different_seed_ok() {
        let seed0 = "[9;32]";
        let signature0 = LamportSignature::generate_key(seed0); 

        let seed1 = "[99;32]";
        let signature1 = LamportSignature::generate_key(seed1);

        assert_ne!(signature0.public.0[0], signature1.public.0[0]);
        assert_ne!(signature0.public.1[0], signature1.public.1[0]);
    }

    #[test]
    fn sign_ok() {
        let seed = "[9;32]";
        let signature = LamportSignature::generate_key(seed); 

        let message = "sakura";
        let sign = signature.sign(message);

        for i in 0..255 {
            assert_ne!(sign[i], sign[i+1]);
        }   
    }

    #[test]
    fn sign_and_verify_ok() {
        let seed = "[9;32]";
        let signature = LamportSignature::generate_key(seed); 

        let message = "sakura";
        let sign = signature.sign(message);

        let result = LamportSignature::verify(signature.public, message, sign);
        assert!(result);
    }

    #[test]
    fn verify_wrong_message_fail() {
        let seed = "[9;32]";
        let signature = LamportSignature::generate_key(seed); 

        let message = "sakura";
        let sign = signature.sign(message);

        let result = LamportSignature::verify(signature.public, "message", sign);
        assert!(!result);
    }

    #[test]
    fn verify_wrong_sign_fail() {
        let seed = "[9;32]";
        let signature = LamportSignature::generate_key(seed); 

        let message = "sakura";
        let sign = signature.public.0;

        let result = LamportSignature::verify(signature.public, message, sign);
        assert!(!result);
    }
}