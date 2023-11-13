#![warn(missing_docs, clippy::suspicious, clippy::pedantic)]
#![allow(clippy::new_without_default)] // `Default` is a very different notion. It should always return the same value.
#![allow(clippy::module_name_repetitions, clippy::wildcard_imports)]
//! This module is a port of Hyperledger Ursa's built-in BLS
//! signature-verify. Only a single key verification is implemented at
//! this point.  The module is meant to initially expose only the SDK
//! changes, which can be easily taken down in size with LTO and
//! should produce more performant, if larger (but not significantly)
//! binaries.  The idea being that single signature verify is quick,
//! and small, and that most of the code overhead can be taken down
//! using LTO.
//!
//! This is by no means a complete implementation, further work is
//! needed to expand the scope and to include changes to the Solana
//! ISA.

pub use instruction::new_bls_12_381_instruction;
use {
    self::algebra::GeneratorPoint,
    algebra::{G1Affine, G2Affine, GroupOrderElement},
    goof::{Mismatch, Outside},
};

/// A pair of keys. You usually want to generate this rather than the [`SignKey`]
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct KeyPair {
    /// The private key.  At present can only be used to create a single signature.
    pub sign: SignKey,
    /// The public key.  At present can only be used to verify a single signature.
    pub verify: VerKey,
}

/// The **Public Key** equivalent for the BLS12-381 cryptography.
#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct VerKey {
    /// The affine point that is used to represent the location along the elliptic curve.
    pub(crate) point: G2Affine,
}

/// The **Private key** equivalent for the BLS12-381 cryptography.
#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct SignKey {
    /// The piece of data that must be known to all parties.
    group_order_element: GroupOrderElement,
}

/// The structure that represents a signature on the BLS12 elliptic curve.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Signature {
    /// The signature as represented in the G1 space of the elliptic curve.
    pub(crate) point: G1Affine,
}

/// Most objects in this module need to be encoded in a fixed-size
/// object, called a Solana instruction. It is thus imperative to
/// encode that information as being a fixed size. If you know that
/// your object can be encoded in *at most* `BYTE_REPR_SIZE`, then
/// implement this trait.
pub trait FixedByteRepr {
    /// The **maximum** size of
    const BYTE_REPR_SIZE: usize;
}

pub mod algebra {
    //! Elliptic curve cryptography at its core is about moving along
    //! the aforementioned elliptic curves in affine coordinates. The
    //! idea being that there are points fixed by some algorithm (and
    //! known to all parties) which pair up and allow one to navigate
    //! the elliptic curve. The ED-family of curves fix one of the
    //! points to be the Edwards point, however the BLS12 family do
    //! not have that. This module is relevant to handling the pairs
    //! of points and affine coordinate locations. For simplicity it
    //! can be regarded as the cryptography part and can be replaced.

    use {
        super::{Error, FixedByteRepr},
        amcl::bn254::{
            big::BIG,
            ecp::ECP,
            ecp2::ECP2,
            fp2::FP2,
            pair::{g1mul, g2mul},
            rom::{self, CURVE_ORDER, CURVE_PXA, CURVE_PXB, CURVE_PYA, CURVE_PYB, MODBYTES},
        },
    };

    /// Pair of points in the affine representation using the [`amcl`] library.
    #[derive(Copy, Clone, PartialEq)]
    #[repr(transparent)]
    pub struct PointPair(pub(crate) amcl::bn254::fp12::FP12);

    impl PointPair {
        /// The equivalent of of performing the operation `e(PointG1,
        /// PointG2, PointG1_1, PointG2_1)` it should yield a
        /// co-ordinate transformation that is closed under the group
        /// operations, as such it is used for verification using the
        /// [`amcl::bn254::pair::isunity`] function.
        #[must_use]
        pub fn pair2(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> Self {
            let mut result =
                amcl::bn254::pair::fexp(&amcl::bn254::pair::ate2(&q.0, &p.0, &s.0, &r.0));
            result.reduce();

            Self(result)
        }
    }

    /// Wrapper for using a hash and generating a `G1` family of group elements from a generic [`hasher`]
    ///
    /// # Errors
    /// - Forwards [`G1Affine::from_hash`] failure
    pub fn hash<T: sha2::Digest>(message: &[u8], mut hasher: T) -> Result<G1Affine, Error> {
        hasher.update(message);
        G1Affine::from_hash(hasher.finalize().as_slice())
    }

    /// The group element in the BLS12 affine coordinates. If this
    /// tells you nothing, consider not touching objects of this type.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[must_use]
    #[repr(transparent)]
    pub struct GroupOrderElement {
        /// Group oirder element as represented by the [AMCL](https://github.com/miracl/amcl) Big number.
        bignum: BIG,
    }

    impl FixedByteRepr for GroupOrderElement {
        const BYTE_REPR_SIZE: usize = MODBYTES;
    }

    impl GroupOrderElement {
        /// Construct a random group element using the [`amcl`] subroutines. See [`random_mod_order`]
        pub fn new() -> Self {
            GroupOrderElement {
                bignum: random_mod_order(),
            }
        }

        /// Generate a [`Self`] using a seed phrase or set of
        /// bytes.
        ///
        /// # Errors
        ///
        /// The length of the slice must be exactly [`MODBYTES`].
        pub fn seeded(seed: &[u8]) -> Result<GroupOrderElement, Error> {
            goof::assert_eq(&seed.len(), &MODBYTES)?;
            // TODO: Consider a separate `struct Seed`
            let mut rng = amcl::rand::RAND::new();
            rng.clean();
            rng.seed(seed.len(), seed);
            Ok(GroupOrderElement {
                bignum: BIG::randomnum(&BIG::new_ints(&CURVE_ORDER), &mut rng),
            })
        }

        /// Convert into a fixed-size bytes representation (that is for some reason passed as a vector).
        #[must_use]
        pub fn to_byte_vec(&self) -> Vec<u8> {
            let mut bn = self.bignum;
            let mut vec = vec![0u8; Self::BYTE_REPR_SIZE];
            bn.tobytes(&mut vec);
            vec
        }

        /// Try to deserialize [`Self`] from a string of bytes. This function is checked.
        ///
        /// # Errors
        /// - If `bytes.len()` is longer than [`Self::BYTES_REPR_SIZE`]
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            // TODO: this was copied from Hyperledger Ursa, but it extremely confusing and ugly. Refactor.
            goof::assert_in(&bytes.len(), &(0..Self::BYTE_REPR_SIZE))?;
            let mut vec = bytes.to_vec(); // TODO: Remove allocation
            let len = vec.len();
            if len < MODBYTES {
                // TODO: No-op?
                let diff = MODBYTES - len;
                let mut result = vec![0; diff];
                result.append(&mut vec);
                Ok(GroupOrderElement {
                    bignum: BIG::frombytes(&result),
                })
            } else {
                Ok(GroupOrderElement {
                    bignum: BIG::frombytes(bytes),
                })
            }
        }
    }

    /// Generate a Random [`BIG`] to be used to represent an affine
    /// coordinate along the elliptic curve.
    ///
    /// # Security
    /// Relies on [`rand`], and inherits all of the CVEs from that library.
    #[must_use]
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
    #[derive(Debug, Clone, Copy, PartialEq)]
    #[must_use]
    #[repr(transparent)]
    pub struct G1Affine(pub(crate) ECP);

    /// An element of the `G2` group represented in Affine coordinates via the [`amcl`] library.
    #[derive(Debug, Clone, Copy, PartialEq)]
    #[must_use]
    #[repr(transparent)]
    pub struct G2Affine(pub(crate) ECP2);

    impl FixedByteRepr for G1Affine {
        const BYTE_REPR_SIZE: usize = MODBYTES * 16;
    }

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
            Self(g1mul(&self.0, &mut bn))
        }
    }

    impl core::ops::Neg for G2Affine {
        type Output = Self;

        fn neg(self) -> Self::Output {
            let mut r = self.0;
            r.neg();
            Self(r)
        }
    }

    impl FixedByteRepr for G2Affine {
        const BYTE_REPR_SIZE: usize = MODBYTES * 4;
    }

    impl G2Affine {
        /// Create a new random `G2` group element.
        pub fn new() -> Self {
            let point_x = {
                let point_x_a = BIG::new_ints(&CURVE_PXA);
                let point_x_b = BIG::new_ints(&CURVE_PXB);
                FP2::new_bigs(&point_x_a, &point_x_b)
            };
            let point_y = {
                let point_y_a = BIG::new_ints(&CURVE_PYA);
                let point_y_b = BIG::new_ints(&CURVE_PYB);
                FP2::new_bigs(&point_y_a, &point_y_b)
            };

            let gen_g2 = ECP2::new_fp2s(&point_x, &point_y);

            let point = g2mul(&gen_g2, &random_mod_order());

            Self(point)
        }

        /// Group multiplication under `G2`.
        pub fn group_mul(&self, goe: &GroupOrderElement) -> Self {
            let r = self.0;
            let bn = goe.bignum;
            Self(g2mul(&r, &bn))
        }

        /// Return representation of [`self`] as a vector of
        /// bytes. The size of the vector is fixed by construction to
        /// be [`Self::BYTE_REPR_SIZE`].
        pub fn to_byte_vec(&self) -> Vec<u8> {
            let mut out_buffer = vec![0u8; Self::BYTE_REPR_SIZE];
            self.0.tobytes(&mut out_buffer);
            out_buffer
        }
    }

    /// The point that must be known to all parties in order for the Elliptic curve cryptography to be useful
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct GeneratorPoint {
        pub(crate) point: G2Affine,
    }

    impl Default for GeneratorPoint {
        fn default() -> Self {
            let seed_buffer = [0_u8; 128];
            Self::from_seed(&seed_buffer).unwrap()
        }
    }

    impl GeneratorPoint {
        /// Construct [`self`] using a random `G2` element.
        #[must_use]
        pub fn new() -> Self {
            Self {
                point: G2Affine::new(),
            }
        }

        /// Construct [`Self`] given a seed of precisely 128 bytes of entropy.
        pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
            let randnum = {
                goof::assert_eq(&seed.len(), &128usize)?;
                let mut rng = amcl::rand::RAND::new();
                rng.clean();
                rng.seed(seed.len(), seed);
                BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), &mut rng)
            };
            let point = {
                let point_x = {
                    let point_x_a = BIG::new_ints(&rom::CURVE_PXA);
                    let point_x_b = BIG::new_ints(&rom::CURVE_PXB);
                    FP2::new_bigs(&point_x_a, &point_x_b)
                };

                let point_y = {
                    let point_y_a = BIG::new_ints(&rom::CURVE_PYA);
                    let point_y_b = BIG::new_ints(&rom::CURVE_PYB);
                    FP2::new_bigs(&point_y_a, &point_y_b)
                };

                G2Affine(amcl::bn254::pair::g2mul(
                    &ECP2::new_fp2s(&point_x, &point_y),
                    &randnum,
                ))
            };

            Ok(Self { point })
        }
    }
}

/// The main Error type used in this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The Seed length is not the right length for what it should be
    #[error("The seed length is not the correct value. {0}")]
    SeedLengthExact(Mismatch<usize>),
    /// The Seed length is not the right length for what it should be
    #[error("The seed length is not the correct value. {0}")]
    SeedLength(Outside<usize>),
}

impl From<Outside<usize>> for Error {
    fn from(value: Outside<usize>) -> Self {
        Self::SeedLength(value)
    }
}

impl From<Mismatch<usize>> for Error {
    fn from(value: Mismatch<usize>) -> Self {
        Self::SeedLengthExact(value)
    }
}

impl FixedByteRepr for VerKey {
    const BYTE_REPR_SIZE: usize = amcl::bn254::rom::MODBYTES * 4;
}

impl VerKey {
    /// Construct [`Self`]
    #[must_use]
    pub fn new(generator_point: GeneratorPoint, sign_key: &SignKey) -> Self {
        let point = generator_point
            .point
            .group_mul(&sign_key.group_order_element);
        VerKey { point }
    }

    /// Allocate and return a byte vector representing [`self`].
    #[must_use]
    pub fn to_byte_vec(&self) -> Vec<u8> {
        self.point.to_byte_vec()
    }
}

impl core::fmt::Debug for SignKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignKey")
            .field("bytes", &self.group_order_element.to_byte_vec())
            .finish()
    }
}

impl core::fmt::Debug for VerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerKey")
            .field("point_bytes", &self.to_byte_vec())
            .finish()
    }
}

impl From<GroupOrderElement> for SignKey {
    fn from(group_order_element: GroupOrderElement) -> Self {
        Self {
            group_order_element,
        }
    }
}

impl FixedByteRepr for SignKey {
    const BYTE_REPR_SIZE: usize = 32;
}

impl SignKey {
    /// Construct [`self`] from a seed.
    ///
    /// # Errors
    /// - Forwards [`GroupOrderElement::seeded`] failure
    pub fn new(seed: Option<&[u8]>) -> Result<Self, Error> {
        Ok(seed
            .map_or_else(|| Ok(GroupOrderElement::new()), GroupOrderElement::seeded)?
            .into())
    }

    /// View [`self`] as `&[u8]`.
    #[must_use]
    pub fn to_byte_vec(&self) -> Vec<u8> {
        self.group_order_element.to_byte_vec()
    }

    /// Construct [`Self`] from a raw byte representation.
    ///
    /// # Errors
    /// - Forwards [`GroupOrderElement::from_bytes`] failure
    pub fn from_bytes(bytes: [u8; Self::BYTE_REPR_SIZE]) -> Result<Self, Error> {
        let group_order_element = GroupOrderElement::from_bytes(&bytes)?;
        Ok(Self {
            group_order_element,
        })
    }

    /// Sign a given array of bytes representing a message.
    ///
    /// # Errors
    /// See [`pair::hash`]
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let point = {
            let hasher = sha2::Sha256::default();
            algebra::hash(message, hasher)?.mul(&self.group_order_element)
        };

        Ok(Signature { point })
    }
}

impl FixedByteRepr for Signature {
    const BYTE_REPR_SIZE: usize = G1Affine::BYTE_REPR_SIZE;
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
    ///
    /// # Errors
    /// - Forwards errors from [`pair::hash`]
    pub fn verify(
        &self,
        message: &[u8],
        verification_key: &VerKey,
        generator: GeneratorPoint,
    ) -> Result<bool, Error> {
        let hashpoint = algebra::hash(message, sha2::Sha256::default())?;
        Ok(amcl::bn254::fp12::FP12::isunity(
            &algebra::PointPair::pair2(
                &self.point,
                &core::ops::Neg::neg(generator.point),
                &hashpoint,
                &verification_key.point,
            )
            .0,
        ))
    }

    /// Convert [`Self`] to a vector of `u8`.
    fn to_byte_vec(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; Self::BYTE_REPR_SIZE];
        self.point.0.tobytes(&mut buffer, false);
        buffer
    }
}

impl KeyPair {
    ///  Create a new key-pair, given seed and generator point seed
    ///
    /// # Explanation
    ///
    /// Elliptic curves are parameterised as 1D objects in something
    /// called affine coordinates, that means that a single integer is
    /// enough to determine the position on the curve. While the
    /// Edwards family of curves has a natural choice for an origin --
    /// the Edwards point, the BLS family has an additional degree of
    /// freedom, so in addition to using a `seed` one must also
    /// specify a generator point. Best way to do so is to use a
    /// `128`-bit seed phrase, which can be anything, but it is my
    /// personal recommendation to use something meaningful to the
    /// Solana library.
    ///
    /// The `private_key_seed` is something else, but we would
    /// recommend enough seed information to produce a similarly
    /// strong object.
    ///
    /// # Errors
    ///
    /// - Forwards [`SignKey::new`] failure
    pub fn new(generator_point: GeneratorPoint) -> Result<Self, Error> {
        let sign = SignKey::new(None)?;
        let verify = VerKey::new(generator_point, &sign);
        Ok(Self { sign, verify })
    }
}

pub mod instruction {
    //! Solana integration.

    use bytemuck::{bytes_of, Pod, Zeroable};

    /// Size of the serialized Public (verficiation) key
    pub const PUBKEY_SERIALIZED_SIZE: usize = VerKey::BYTE_REPR_SIZE;
    /// Size of the serialized single signature
    pub const SIGNATURE_SERIALIZED_SIZE: usize = Signature::BYTE_REPR_SIZE;
    /// Offset(s) for Signature; not used yet.
    pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
    /// The Signature offset start, required because [`bytemuck`]
    /// requires structures to be aligned
    pub const SIGNATURE_OFFSET_START: usize = 16 - SIGNATURE_OFFSETS_SERIALIZED_SIZE; // TODO: Come up with a more reliable way of ensuring alignment
    /// The start of the data offset. This is a dependent constant, not to be tweaked manually.
    pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSET_START;

    /// Signature offsets packed into a single object.
    #[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
    #[repr(C)]
    pub struct Bls12381SignatureOffsets {
        /// Offset to ed25519 signature of 64 bytes
        signature_offset: u16,
        /// Instruction index to find signature
        signature_instruction_index: u16,
        /// Offset to public key of 32 bytes
        public_key_offset: u16,
        /// Instruction index to find public key
        public_key_instruction_index: u16,
        /// Offset to start of message data
        message_data_offset: u16,
        /// Size of message data
        message_data_size: u16,
        /// Index of instruction data to get message data
        message_instruction_index: u16,
    }

    use {super::*, crate::instruction::Instruction};

    /// Construct an instruction to be used by Solana programs.
    ///
    /// # Errors
    /// - If signing the message fails.
    ///
    /// # Panics
    ///
    /// These panics are only present in debug builds, which should
    /// protect you if you run the tests, but not in the wild.  
    /// - If any of the length assersions fail.
    /// - If any of the length assets are longer than what would fit into `u16`
    #[must_use]
    pub fn new_bls_12_381_instruction(key: &KeyPair, message: &[u8]) -> Result<Instruction, Error> {
        // FIXME: SATURATION IS NOT WHAT WE WANT IN ANY OF THE ARITHMETIC HERE.
        let signature = key.sign.sign(message)?.to_byte_vec();
        debug_assert_eq!(
            signature.len(),
            SIGNATURE_SERIALIZED_SIZE,
            "Signature length has unexpected value. This is not a safe state, aborting"
        );

        let pubkey = key.verify.to_byte_vec();
        debug_assert_eq!(
            pubkey.len(),
            PUBKEY_SERIALIZED_SIZE,
            "Public Key length has an unexpected value. This is not a safe state, aborting"
        );

        let mut instruction_data = Vec::with_capacity(
            DATA_START
                .saturating_add(SIGNATURE_SERIALIZED_SIZE)
                .saturating_add(PUBKEY_SERIALIZED_SIZE)
                .saturating_add(message.len()),
        );

        let num_signatures = 1u8;
        let public_key_offset = DATA_START;
        let signature_offset = public_key_offset.saturating_add(PUBKEY_SERIALIZED_SIZE);
        let message_data_offset = signature_offset
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .try_into()
            .expect("Message data offset too large for u16");
        // FIXME: this assumes one byte to align.
        instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));
        debug_assert_eq!(instruction_data.len(), 2);
        let offsets = Bls12381SignatureOffsets {
            signature_offset: signature_offset
                .try_into()
                .expect("Signature offset doesn't fit into u16"),
            signature_instruction_index: u16::MAX,
            public_key_offset: public_key_offset
                .try_into()
                .expect("Public key offset doesn't fit into u16"),
            public_key_instruction_index: u16::MAX,
            message_data_offset,
            message_data_size: message
                .len()
                .try_into()
                .expect("Message too long to fit into u16"),
            message_instruction_index: u16::MAX,
        };

        instruction_data.extend_from_slice(bytes_of(&offsets));
        debug_assert_eq!(
            instruction_data.len(),
            public_key_offset,
            "Public Key offset"
        );
        instruction_data.extend_from_slice(&pubkey);
        debug_assert_eq!(instruction_data.len(), signature_offset, "Signature offset");
        instruction_data.extend_from_slice(&signature);
        debug_assert_eq!(
            instruction_data.len(),
            message_data_offset as usize,
            "message_data_offset"
        );
        instruction_data.extend_from_slice(message);

        Ok(Instruction {
            program_id: solana_sdk::bls12_381_program::id(),
            accounts: Vec::new(),
            data: instruction_data,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::bls12_381_instruction::{instruction, GeneratorPoint, KeyPair, SignKey, VerKey};

    #[test]
    fn sign_key_as_bytes_non_empty() {
        let sign_key = SignKey::new(None).unwrap();
        let bytes = sign_key.to_byte_vec();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn generator_point_crypto_safe() {
        let gen = GeneratorPoint::new();
        assert!(gen != GeneratorPoint::default(), "If you managed to recreate the default generator point, then the cryptographic assumptions are false, and this is no longer cryptographically safe. ");
    }

    #[test]
    /// # ATTENTION:
    ///
    /// This test is important, if it breaks, you have broken the ABI.
    fn sign_key_from_bytes() {
        let bytes: [u8; 32] = [
            3, 19, 158, 223, 233, 207, 232, 184, 106, 205, 198, 32, 14, 2, 215, 75, 44, 68, 21,
            249, 101, 117, 78, 111, 104, 212, 94, 56, 36, 156, 44, 59,
        ];
        let sign_key = SignKey::from_bytes(bytes.clone()).unwrap();
        assert_eq!(sign_key.to_byte_vec(), bytes);
    }

    #[test]
    fn sig_verify() {
        let message = [1, 2, 3, 4, 5];

        let gen = GeneratorPoint::new();
        let sign_key = SignKey::new(None).unwrap();
        let ver_key = VerKey::new(gen, &sign_key);
        let signature = sign_key.sign(&message).unwrap();

        assert!(
            signature.verify(&message, &ver_key, gen).unwrap(),
            "Failed to verify signature for message [1,2,3,4,5]"
        );

        let different_message = [2, 3, 4, 5, 6];

        let different_message_signature = sign_key.sign(&different_message).unwrap();
        // assert_ne!(signature, different_message_signature);
        assert!(
            different_message_signature
            .verify(&different_message, &ver_key, gen)
            .unwrap(),
            "Couldn't verify the signature on `different_message`, probably because the signature has become non-deterministic."
            );
        assert!(!different_message_signature
            .verify(&message, &ver_key, gen)
            .unwrap(),
            "The signature for two different trivial messages is the exact same. This should never happen, and you should report it"
            );

        let different_gen = GeneratorPoint::new();
        let different_gen_signature = sign_key.sign(&message).unwrap();
        // assert_ne!(signature, different_gen_signature);
        assert!(
            !different_gen_signature
            .verify(&message, &ver_key, different_gen)
            .unwrap(),
            "Different generator points cannot be paired post-hoc."
        );

        let different_sign_key = SignKey::new(None).unwrap();
        let different_key_signature = different_sign_key.sign(&message).unwrap();
        assert!(
            !different_key_signature
            .verify(&message, &ver_key, different_gen)
            .unwrap(),
            "Different sign keys should not produce a valid verification; points cannot be paired post-hoc."
        );
    }

    #[test]
    fn instruction_test() {
        let key_pair = KeyPair::new(GeneratorPoint::default()).expect("Failed to create key pair");
        let message = b"Hello world";
        let instruction = instruction::new_bls_12_381_instruction(&key_pair, message);
        println!("{instruction:?}");
    }
}

// Local Variables:
// mode: rust-ts
// eval: (apheleia-mode)
// eval: (aggressive-indent-mode)
// jinx-local-words: "Hyperledger amcl deserialize hasher isunity len sig struct"
// End:
