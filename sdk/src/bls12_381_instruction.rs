/// This module is a port of Hyperledger Ursa's built-in BLS
/// sig-verify. Only a single key verification is implemented at this
/// point.
use pair::{G1Affine, G2Affine, GroupOrderElement};
pub const SECRET_KEY_LENGTH: usize = 32;

pub mod pair {
    use {
        super::Error,
        amcl::bn254::{big::BIG, ecp::ECP, ecp2::ECP2, rom::CURVE_ORDER},
    };

    #[derive(Copy, Clone, PartialEq)]
    pub struct Pair(pub(crate) amcl::bn254::fp12::FP12);

    impl Pair {
        /// e(PointG1, PointG2, PointG1_1, PointG2_1)
        pub fn pair2(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> Self {
            let mut result =
                amcl::bn254::pair::fexp(&amcl::bn254::pair::ate2(&q.0, &p.0, &s.0, &r.0));
            result.reduce();

            Self(result)
        }
    }

    pub fn hash<T: sha2::Digest>(message: &[u8], mut hasher: T) -> Result<G1Affine, Error> {
        hasher.update(message);
        G1Affine::from_hash(hasher.finalize().as_slice())
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct GroupOrderElement {
        bignum: BIG,
    }

    impl GroupOrderElement {
        pub const BYTES_REPR_SIZE: usize = amcl::bn254::rom::MODBYTES;

        pub fn new() -> Result<Self, Error> {
            Ok(GroupOrderElement {
                bignum: random_mod_order()?,
            })
        }

        pub fn seeded(seed: &[u8]) -> Result<GroupOrderElement, Error> {
            if seed.len() != Self::BYTES_REPR_SIZE {
                // goof::Mismatch{expect: Self::BYTES_REPR_SIZE, actual: seed.len()}
                todo!()
            } else {
                // TODO: Consider a separate `struct Seed`
                let mut rng = amcl::rand::RAND::new();
                rng.clean();
                rng.seed(seed.len(), seed);
                Ok(GroupOrderElement {
                    bignum: BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng),
                })
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bn = self.bignum;
            let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
            bn.tobytes(&mut vec);
            vec
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            // TODO: this was copied from Hyperledger ursa, but it extremely confusing and ugly. Refactor.
            if bytes.len() > Self::BYTES_REPR_SIZE {
                todo!()
            } else {
                let mut vec = bytes.to_vec(); // TODO: Remove allocation
                let len = vec.len();
                if len < amcl::bn254::rom::MODBYTES {
                    // TODO: No-op?
                    let diff = amcl::bn254::rom::MODBYTES - len;
                    let mut result = vec![0; diff];
                    result.append(&mut vec);
                    return Ok(GroupOrderElement {
                        bignum: BIG::frombytes(&result),
                    });
                } else {
                    Ok(GroupOrderElement {
                        bignum: BIG::frombytes(bytes),
                    })
                }
            }
        }
    }

    pub fn random_mod_order() -> Result<BIG, Error> {
        use rand::RngCore as _;

        let entropy_bytes = 128;
        let mut seed = vec![0_u8; entropy_bytes];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(seed.as_mut_slice());
        let mut rng = amcl::rand::RAND::new();
        rng.clean();
        // AMCL recommends to initialise from at least 128 bytes, check doc for `RAND.seed`
        rng.seed(entropy_bytes, &seed);
        Ok(BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng))
    }

    #[derive(Debug, Clone, Copy)]
    pub struct G2Affine(pub(crate) ECP2);

    #[derive(Debug, Clone, Copy)]
    pub struct G1Affine(pub(crate) ECP);

    impl G1Affine {
        pub fn from_hash(hash_bytes: &[u8]) -> Result<Self, super::Error> {
            let mut element = GroupOrderElement::from_bytes(hash_bytes)?;

            let mut point = ECP::new_big(&element.bignum);
            while point.is_infinity() {
                element.bignum.inc(1);
                point = ECP::new_big(&element.bignum);
            }

            Ok(G1Affine(point))
        }

        pub fn mul(&self, element: &GroupOrderElement) -> Result<G1Affine, Error> {
            let mut bn: BIG = element.bignum;
            Ok(Self(amcl::bn254::pair::g1mul(&self.0, &mut bn)))
        }
    }

    impl G2Affine {
        pub fn neg(self) -> Self {
            let mut r = self.0;
            r.neg();
            Self(r)
        }
    }
}

pub enum Error {
    Other(&'static str),
}

pub struct VerKey {
    pub(crate) point: G2Affine,
    // bytes: Vec<u8>,             // TODO: avoid allocation?
}

pub struct SignKey {
    group_order_element: GroupOrderElement,
    bytes: Vec<u8>,
}

impl From<GroupOrderElement> for SignKey {
    fn from(group_order_element: GroupOrderElement) -> Self {
        Self {
            group_order_element,
            bytes: group_order_element.to_bytes(),
        }
    }
}

impl SignKey {
    pub fn new(seed: Option<&[u8]>) -> Result<SignKey, Error> {
        Ok(seed
            .map(GroupOrderElement::seeded)
            .unwrap_or_else(GroupOrderElement::new)?
            .into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let point = {
            let hasher = sha2::Sha256::default();
            pair::hash(message, hasher)?.mul(&self.group_order_element)
        }?;

        Ok(Signature { point })
    }
}

#[derive(Debug)]
pub struct Signature {
    pub(crate) point: G1Affine,
    // bytes: Vec<u8>,
}

pub struct Generator {
    point: G2Affine,
}

impl Signature {
    /// Verify the BLS12-381 signature provided the following data:
    ///
    /// # Arguments
    /// `message` - the message that had been signed, represented as a slice of bytes.
    /// `verification_key` - the `public_key` equivalent for the BLS12-381 signature scheme.
    /// `generator` - the generator that was used to generate the signing key.
    ///
    /// It is assumed that the `message`, and `generator` are both
    /// known to all parties.
    pub fn verify(
        &self,
        message: &[u8],
        verification_key: &VerKey,
        generator: Generator,
    ) -> Result<bool, Error> {
        let hashpoint = pair::hash(message, sha2::Sha256::default())?;
        Ok(amcl::bn254::fp12::FP12::isunity(
            &pair::Pair::pair2(
                &self.point,
                &generator.point.neg(),
                &hashpoint,
                &verification_key.point,
            )
            .0,
        ))
    }
}

pub struct KeyPair {
    pub sign: SignKey,
    pub verify: VerKey,
}

pub fn new_bls_12_381_instruction(key: &KeyPair, thing: &[u8]) -> crate::instruction::Instruction {
    todo!()
}

pub fn generate_key(rng: &mut rand::rngs::ThreadRng) -> KeyPair {
    todo!()
}
