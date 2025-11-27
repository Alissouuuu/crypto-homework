use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey as DhPublicKey};
use sha2::{Digest, Sha256};

/// Represent a person (Alice or Bob) in the Signed DH protocol
pub struct Party {
    // Private key for the signature
    signing_key: SigningKey,
    // Public key for the signature (to share)
    pub verifying_key: VerifyingKey,

    // Private ephemeral DH key (Option cause it will be consumed)
    dh_secret: Option<EphemeralSecret>,
    // Public DH key (to share)
    pub dh_public: DhPublicKey,
}

impl Party {
    /// Create a new person with new fresh keys
    pub fn new() -> Self {
        // We use the p256's randomizer to get random numbers
        let mut rng = p256::elliptic_curve::rand_core::OsRng;

        // Generate pair of keys for the signature
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Generate pair of DH keys
        let dh_secret = EphemeralSecret::random(&mut rng);
        let dh_public = DhPublicKey::from(&dh_secret);

        Party {
            signing_key,
            verifying_key,
            dh_secret: Some(dh_secret),
            dh_public,
        }
    }

    /// Sign the public DH key
    /// The signature assure that the DH key belongs to this person
    pub fn sign_dh_public(&self) -> Signature {
        // Encode the public DH key in bytes
        let dh_public_bytes = self.dh_public.to_sec1_bytes();

        // Hash bytes
        let mut hasher = Sha256::new();
        hasher.update(&dh_public_bytes);
        let hash = hasher.finalize();

        // Sign hash
        self.signing_key.sign(&hash)
    }

    /// Verify the DH public key signture from another person
    pub fn verify_peer_dh_public(
        peer_verifying_key: &VerifyingKey,
        peer_dh_public: &DhPublicKey,
        signature: &Signature,
    ) -> Result<(), &'static str> {
        // Encode peer's DH public key
        let peer_dh_bytes = peer_dh_public.to_sec1_bytes();

        // Hash bytes
        let mut hasher = Sha256::new();
        hasher.update(&peer_dh_bytes);
        let hash = hasher.finalize();

        // Verifies the signature
        peer_verifying_key
            .verify(&hash, signature)
            .map_err(|_| "Signature verification failed")
    }

    /// Calculate the shared secret with the peer's DH public key
    /// Use the ephemeral DH key (one use)
    pub fn compute_shared_secret(&mut self, peer_dh_public: &DhPublicKey) -> Vec<u8> {
        // Take ephemeral secret's ownership
        let dh_secret = self.dh_secret.take().expect("DH secret already consumed");

        // Make Diffie-Hellman exchange
        let shared_secret = dh_secret.diffie_hellman(peer_dh_public);

        // Convert in bytes
        shared_secret.raw_secret_bytes().to_vec()
    }
}

/// Protocol demonstration fonction
pub fn demonstrate_signed_dh() {
    println!("=== Task 1: Signed Diffie-Hellman Protocol ===\n");

    // 1. Alice and Bob generate their keys
    println!("1. Alice and Bob generate their keys ...");
    let mut alice = Party::new();
    let mut bob = Party::new();
    println!("-> Keys generated !\n");

    // 2. Alice sign her DH public key
    println!("2. Alice sign her DH public key ...");
    let alice_signature = alice.sign_dh_public();
    println!(
        "-> Signature created: {:02x?} ...\n",
        &alice_signature.to_bytes()[..8]
    );

    // 3. Bob sign his DH public key
    println!("3. Bob sign his DH public key ...");
    let bob_signature = bob.sign_dh_public();
    println!(
        "-> Signature created: {:02x?} ...\n",
        &bob_signature.to_bytes()[..8]
    );

    // 4. Alice verfies Bob's signature
    println!("4. Alice verfies Bob's signature ...");
    match Party::verify_peer_dh_public(&bob.verifying_key, &bob.dh_public, &bob_signature) {
        Ok(_) => println!("-> Bob's signature verified with success !\n"),
        Err(e) => {
            println!("ERROR: {}\n", e);
            return;
        }
    }

    // 5. Bob verfies Alice's signature
    println!("5. Bob verfies Alice's signature ...");
    match Party::verify_peer_dh_public(&alice.verifying_key, &alice.dh_public, &alice_signature) {
        Ok(_) => println!("-> Alice's signature verified with success !\n"),
        Err(e) => {
            println!("ERROR: {}\n", e);
            return;
        }
    }

    // 6. Alice and Bob calculate the shared secret
    println!("6. Alice and Bob calculate the shared secret ...");

    // Save public keys before consume secrets
    let alice_dh_public = alice.dh_public.clone();
    let bob_dh_public = bob.dh_public.clone();

    let alice_shared = alice.compute_shared_secret(&bob_dh_public);
    let bob_shared = bob.compute_shared_secret(&alice_dh_public);

    // 7. Verification that secrets are the same
    println!("7. Verification that secrets are the same ...");
    if alice_shared == bob_shared {
        println!("-> Shared secrets are the same !");
        println!("Secret (Fisrt 16 bytes): {:02x?}", &alice_shared[..16]);
    } else {
        println!("EROOR: Secrets are not the same !");
    }

    println!("\n=== Signed DH protocol finished with success ! ===\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_dh_protocol() {
        // Create two people
        let mut alice = Party::new();
        let mut bob = Party::new();

        // Exchange the signatures
        let alice_sig = alice.sign_dh_public();
        let bob_sig = bob.sign_dh_public();

        // Verify the signatures
        assert!(Party::verify_peer_dh_public(&bob.verifying_key, &bob.dh_public, &bob_sig).is_ok());

        assert!(
            Party::verify_peer_dh_public(&alice.verifying_key, &alice.dh_public, &alice_sig)
                .is_ok()
        );

        // Save the public keys
        let alice_dh_public = alice.dh_public.clone();
        let bob_dh_public = bob.dh_public.clone();

        // Calculate the shared secerts
        let alice_shared = alice.compute_shared_secret(&bob_dh_public);
        let bob_shared = bob.compute_shared_secret(&alice_dh_public);

        // Verification
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_key() {
        let alice = Party::new();
        let eve = Party::new();

        let alice_sig = alice.sign_dh_public();

        // Eve tries to pretending to be Alice
        // Verfication must fail
        assert!(Party::verify_peer_dh_public(
            &eve.verifying_key, // Wrong key
            &alice.dh_public,
            &alice_sig
        )
        .is_err());
    }

    #[test]
    #[should_panic(expected = "DH secret already consumed")]
    fn test_cannot_reuse_dh_secret() {
        let mut alice = Party::new();
        let bob = Party::new();

        // First use of the DH secret
        let _ = alice.compute_shared_secret(&bob.dh_public);

        // Second use must panic
        let _ = alice.compute_shared_secret(&bob.dh_public);
    }
}
