#![warn(missing_docs)]
//! This module is a port of Hyperledger Ursa's built-in BLS
//! sig-verify. Only a single key verification is implemented at this
//! point.

use pair::{G1Affine, G2Affine, GroupOrderElement};

/// The length of private (or secret) keys.
pub const SECRET_KEY_LENGTH: usize = 32;

pub mod pair {
    //! The elliptic curve cryptography at its core is about moving
    //! along the elliptic curves in affine coordinates. The idea
    //! being that there are points fixed by some algorithm (and known
    //! to all parties) which pair up and allow one to navigate the
    //! elliptic curve. The ED-family of curves fix one of tyhe points
    //! to be the Edwards point, however the BLS12 family do not have
    //! that. This module is relevant to handling the pairs of points
    //! and affine coordinate locations. For simplicity it can be
    //! regarded as the cryptography part and can be replaced.

    use {
        super::Error,
        amcl::bn254::{
            big::BIG,
            ecp::ECP,
            ecp2::ECP2,
            fp2::FP2,
            rom::{CURVE_ORDER, CURVE_PXA, CURVE_PXB, CURVE_PYA, CURVE_PYB, MODBYTES},
        },
    };

    /// Pair of points in the affine representation using the [`amcl`] library.
    #[derive(Copy, Clone, PartialEq)]
    pub struct Pair(pub(crate) amcl::bn254::fp12::FP12);

    impl Pair {
        /// The equivalent of of performing the operation \(e(PointG1,
        /// PointG2, PointG1_1, PointG2_1)\) it should yield a
        /// co-ordinate transformation that is closed under the group
        /// operations, as such it is used for verification using the
        /// [`amcl::bn254::pair::isunity`] function.
        pub fn pair2(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> Self {
            let mut result =
                amcl::bn254::pair::fexp(&amcl::bn254::pair::ate2(&q.0, &p.0, &s.0, &r.0));
            result.reduce();

            Self(result)
        }
    }

    /// Wrapper for using a hash and generating a `G1` family of group elements from a generic [`hasher`]
    pub fn hash<T: sha2::Digest>(message: &[u8], mut hasher: T) -> Result<G1Affine, Error> {
        hasher.update(message);
        G1Affine::from_hash(hasher.finalize().as_slice())
    }

    /// The group element in the BLS12 affine coordinates. If this
    /// tells you nothing, consider not touching objects of this type.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct GroupOrderElement {
        bignum: BIG,
    }

    impl GroupOrderElement {
        /// Fixed size representation length for [`Self`]
        pub const BYTES_REPR_SIZE: usize = MODBYTES;

        /// Construct a random group element using the [`amcl`] subroutines. See [`random_mod_order`]
        pub fn new() -> Self {
            GroupOrderElement {
                bignum: random_mod_order(),
            }
        }

        /// Generate a [`Self`] using a seed phrase or set of bytes. The length of the slice must be exactly the lenght of [`MODBYTES`].
        pub fn seeded(seed: &[u8]) -> Result<GroupOrderElement, Error> {
            if seed.len() != MODBYTES {
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

        /// Convert into a fixed-size bytes representation (that is for some reason passed as a vector).
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bn = self.bignum;
            let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
            bn.tobytes(&mut vec);
            vec
        }

        /// Try to deserialize [`Self`] from a string of bytes. This function is checked.
        ///
        /// # Errors
        /// - If `bytes.len()` is longer than [`Self::BYTES_REPR_SIZE`]
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            // TODO: this was copied from Hyperledger ursa, but it extremely confusing and ugly. Refactor.
            if bytes.len() > Self::BYTES_REPR_SIZE {
                todo!()
            } else {
                let mut vec = bytes.to_vec(); // TODO: Remove allocation
                let len = vec.len();
                if len < MODBYTES {
                    // TODO: No-op?
                    let diff = MODBYTES - len;
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

    /// Generate a Random [`BIG`] to be used to represent an affine
    /// coordinate along the elliptic curve.
    ///
    /// # Security
    /// Relies on [`rand`], and inherits all of the CVEs from that library.
    pub fn random_mod_order() -> BIG {
        use rand::RngCore as _;

        let entropy_bytes = 128;
        let mut seed = vec![0_u8; entropy_bytes];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(seed.as_mut_slice());
        let mut rng = amcl::rand::RAND::new();
        rng.clean();
        // AMCL recommends to initialise from at least 128 bytes, check doc for `RAND.seed`
        rng.seed(entropy_bytes, &seed);
        BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng)
    }

    /// An element of the `G1` group, represented in Affine coordinates via the [`amcl`] library.
    #[derive(Debug, Clone, Copy)]
    pub struct G1Affine(pub(crate) ECP);

    /// An element of the `G2` group represented in Affine coordinates via the [`amcl`] library.
    #[derive(Debug, Clone, Copy)]
    pub struct G2Affine(pub(crate) ECP2);

    impl G1Affine {
        /// Produce [`Self`] from a set of `hash_bytes`. See
        /// # Errors
        /// `hash_bytes` is used as input to [`GroupOrderElement::from_bytes`]
        pub fn from_hash(hash_bytes: &[u8]) -> Result<Self, super::Error> {
            let mut element = GroupOrderElement::from_bytes(hash_bytes)?;

            let mut point = ECP::new_big(&element.bignum);
            while point.is_infinity() {
                element.bignum.inc(1);
                point = ECP::new_big(&element.bignum);
            }

            Ok(G1Affine(point))
        }

        /// Group multiplication of [`self`] and another group element.
        pub fn mul(&self, element: &GroupOrderElement) -> G1Affine {
            let mut bn: BIG = element.bignum;
            Self(amcl::bn254::pair::g1mul(&self.0, &mut bn))
        }
    }

    impl G2Affine {
        /// Fixed size representation length of the object.
        pub const BYTES_REPR_SIZE: usize = MODBYTES * 4;

        /// Unary group negation for `G2`.
        pub fn neg(self) -> Self {
            let mut r = self.0;
            r.neg();
            Self(r)
        }

        /// Create a new random `G2` group element.
        pub fn new() -> G2Affine {
            let point_xa = BIG::new_ints(&CURVE_PXA);
            let point_xb = BIG::new_ints(&CURVE_PXB);
            let point_ya = BIG::new_ints(&CURVE_PYA);
            let point_yb = BIG::new_ints(&CURVE_PYB);

            let point_x = FP2::new_bigs(&point_xa, &point_xb);
            let point_y = FP2::new_bigs(&point_ya, &point_yb);

            let gen_g2 = ECP2::new_fp2s(&point_x, &point_y);

            let point = amcl::bn254::pair::g2mul(&gen_g2, &random_mod_order());

            Self(point)
        }

        /// Group multiplication under `G2`.
        pub fn mul(&self, goe: &GroupOrderElement) -> Self {
            let r = self.0;
            let bn = goe.bignum;
            Self(amcl::bn254::pair::g2mul(&r, &bn))
        }
    }
}

/// The main Error type used in this crate.
pub enum Error {
    /// Other error variant that is not listed above.
    Other(&'static str),
}

/// The **Public Key** equivalent for the BLS12-381 cryptography.
pub struct VerKey {
    pub(crate) point: G2Affine,
}

impl VerKey {
    /// Construct [`Self`]
    pub fn new(generator_point: GeneratorPoint, sign_key: &SignKey) -> Result<Self, Error> {
        let point = generator_point.point.mul(&sign_key.group_order_element);
        Ok(VerKey { point })
    }
}

/// The **Private key** equivalent for the BLS12-381 cryptography.
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
    /// Construct [`self`] from a seed.
    pub fn new(seed: Option<&[u8]>) -> Result<SignKey, Error> {
        Ok(seed
            .map(GroupOrderElement::seeded)
            .unwrap_or_else(|| Ok(GroupOrderElement::new()))?
            .into())
    }

    /// View [`self`] as `&[u8]`.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Sign a given array of bytes representing a message.
    ///
    /// # Errors
    /// See [`pair::hash`]
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let point = {
            let hasher = sha2::Sha256::default();
            pair::hash(message, hasher)?.mul(&self.group_order_element)
        };

        Ok(Signature { point })
    }
}

/// The point that must be known to all parties in order for the Elliptic curve cryptography to be useful
pub struct GeneratorPoint {
    point: G2Affine,
}

impl GeneratorPoint {
    /// Construct [`self`] using a random `G2` element.
    pub fn new() -> Self {
        Self {
            point: G2Affine::new(),
        }
    }
}

/// The structure that represents a signature on the BLS12 elliptic curve.
#[derive(Debug)]
pub struct Signature {
    pub(crate) point: G1Affine,
    // bytes: Vec<u8>,
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
        generator: GeneratorPoint,
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

/// A pair of keys. You usually want to generate this rather than the [`SignKey`]
pub struct KeyPair {
    /// The private key
    pub sign: SignKey,
    /// The public key
    pub verify: VerKey,
}

pub mod instruction {
    //! Solana integration.

    use super::*;

    /// Construct an instruction to be used by Solana programs.
    pub fn new_bls_12_381_instruction(
        key: &KeyPair,
        thing: &[u8],
    ) -> crate::instruction::Instruction {
        todo!()
    }
}

pub use instruction::new_bls_12_381_instruction;

/// Public function to generate a key-pair given a specific thread rng.
pub fn generate_key(rng: &mut rand::rngs::ThreadRng) -> KeyPair {
    todo!()
}

// Local Variables:
// mode: rust-ts
// eval: (apheleia-mode)
// eval: (aggressive-indent-mode)
// End: