use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::Field;
use p256::elliptic_curve::PrimeField;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    Scalar,
};
use sha2::{Digest, Sha256};

/// Sign a message with ECDSA using a specific nonce
/// Normally, ECDSA generates a random k. Here, it is forced to simulate the attack
fn sign_with_fixed_nonce(
    signing_key: &SigningKey,
    message: &[u8],
    k: &Scalar,
) -> (Scalar, Scalar, [u8; 32]) {
    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let z = Scalar::from_repr(hash).unwrap();

    // Calculate R = k·G
    let g = p256::ProjectivePoint::GENERATOR;
    let r_point = g * k;
    let r_affine = r_point.to_affine();

    // Extract r
    let r_encoded = r_affine.to_encoded_point(false);
    let r_bytes = r_encoded.x().unwrap();
    let r = Scalar::from_repr((*r_bytes).into()).unwrap();

    // Retrieve the private key of d
    let d_bytes = signing_key.to_bytes();
    let d = Scalar::from_repr(d_bytes.into()).unwrap();

    // Calculate s = k^(-1) · (z + r·d) mod n
    let k_inv = k.invert().unwrap();
    let s = k_inv * (z + r * d);

    (r, s, hash.into())
}

/// Retrieves the nonce k from two signatures with the same k
fn recover_nonce(
    hash1: &[u8; 32],
    r1: &Scalar,
    s1: &Scalar,
    hash2: &[u8; 32],
    r2: &Scalar,
    s2: &Scalar,
) -> Option<Scalar> {
    // Verify that r1 == r2 (same k used)
    if r1 != r2 {
        println!("-> ERROR: r1 != r2, the signatures do not use the same k !");
        return None;
    }

    // Converts hashes to Scalar
    let z1 = Scalar::from_repr((*hash1).into()).unwrap();
    let z2 = Scalar::from_repr((*hash2).into()).unwrap();

    // Calculate k = (z1 - z2) / (s1 - s2) mod n
    let numerator = z1 - z2;
    let denominator = s1 - s2;

    // If s1 == s2, we cannot recover k
    let denom_inv = denominator.invert();
    if denom_inv.is_none().into() {
        println!("   ✗ Erreur: s1 == s2, impossible de récupérer k");
        return None;
    }

    let k = numerator * denom_inv.unwrap();
    Some(k)
}

/// Retrieves the private key d from k
fn recover_private_key(k: &Scalar, hash: &[u8; 32], r: &Scalar, s: &Scalar) -> Scalar {
    // d = (s·k - z) / r mod n
    let z = Scalar::from_repr((*hash).into()).unwrap();

    let numerator = s * k - z;
    let r_inv = r.invert().unwrap();
    let d = numerator * r_inv;

    d
}

/// ECDSA attack demonstration
pub fn demonstrate_ecdsa_attack() {
    println!("\n=== Task 3: ECDSA Randomness Reuse Attack ===\n");

    // 1. Key generation
    println!("1. 1. Key generation ...");
    let mut rng = p256::elliptic_curve::rand_core::OsRng;
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    println!("-> 1. Key generated !\n");

    // 2. Generation of a nonce k (which will be reused - VULNERABILITY!)
    println!("2. Generation of a nonce k (which will be reused - VULNERABILITY!) ...");
    let k = Scalar::random(&mut rng);
    println!("-> Nonce k generated: {:?}...\n", &k.to_bytes()[..8]);

    // 3. Signing two different messages with the SAME k
    println!("3. 3. Signing two different messages with the SAME k ...");
    let message1 = b"Message number 1";
    let message2 = b"Message number 2 (different)";

    let (r1, s1, hash1) = sign_with_fixed_nonce(&signing_key, message1, &k);
    let (r2, s2, hash2) = sign_with_fixed_nonce(&signing_key, message2, &k);

    println!("   Message 1: {:?}", String::from_utf8_lossy(message1));
    println!(
        "   Signature 1: r = {:?}..., s = {:?}...",
        &r1.to_bytes()[..8],
        &s1.to_bytes()[..8]
    );
    println!("   Message 2: {:?}", String::from_utf8_lossy(message2));
    println!(
        "   Signature 2: r = {:?}..., s = {:?}...",
        &r2.to_bytes()[..8],
        &s2.to_bytes()[..8]
    );
    println!("-> Two signatures created with the same k !\n");

    // 4. Verification that r1 == r2 (proof that k is the same)
    println!("4. Verification that r1 == r2 ...");
    if r1 == r2 {
        println!("-> r1 == r2: The same nonce k was used !\n");
    } else {
        println!("r1 != r2: Implementation error !\n");
        return;
    }

    // 5. ATTACK: Retrieve nonce k
    println!("5. ATTACK: Retrieve nonce k ...");
    let recovered_k = match recover_nonce(&hash1, &r1, &s1, &hash2, &r2, &s2) {
        Some(k) => {
            println!("-> Nonce k successfully recovered !");
            k
        }
        None => {
            println!("-> Failure to recover the nuncio");
            return;
        }
    };

    // Verification that k is correct
    if k == recovered_k {
        println!("-> k recovered == k original: ATTACK SUCCESSFUL !\n");
    } else {
        println!("-> k recovered != k original: Error in the attack\n");
        return;
    }

    // 6. ATTACK: Retrieving the private key of d
    println!("6. ATTACK: Retrieving the private key of d ...");
    let recovered_d = recover_private_key(&recovered_k, &hash1, &r1, &s1);

    // Retrieving the actual private key for comparison
    let d_bytes = signing_key.to_bytes();
    let original_d = Scalar::from_repr(d_bytes.into()).unwrap();

    if recovered_d == original_d {
        println!("-> Private key successfully recovered !");
        println!("-> recovered d == original d: PRIVATE KEY COMPROMISED !\n");
    } else {
        println!("-> d retrieved != d original\n");
        return;
    }

    // 7. Proof: Create a new signature with the retrieved key
    println!("7. Proof: Create a new signature with the retrieved key ...");
    let new_message = b"Message signed with the stolen key !";

    // Create a new signing key from the retrieved key
    let recovered_signing_key = SigningKey::from_bytes(&recovered_d.to_bytes().into())
        .expect("Failed to create signing key");

    let new_signature: Signature = recovered_signing_key.sign(new_message);

    // Verify with the original public key
    use p256::ecdsa::signature::Verifier;
    match verifying_key.verify(new_message, &new_signature) {
        Ok(_) => {
            println!("-> Signature successfully verified !");
            println!("-> The attacker can now sign any message !\n");
        }
        Err(_) => {
            println!("-> Verification failed\n");
            return;
        }
    }

    println!("=== COMPLETE ATTACK : The private key has been recovered ! ===");
    println!("\n LESSON: NEVER reuse the same nonce k in ECDSA !");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_attack() {
        let mut rng = p256::elliptic_curve::rand_core::OsRng;
        let signing_key = SigningKey::random(&mut rng);

        // Generates a fixed k
        let k = Scalar::random(&mut rng);

        // Sign two messages
        let (r1, s1, hash1) = sign_with_fixed_nonce(&signing_key, b"message1", &k);
        let (r2, s2, hash2) = sign_with_fixed_nonce(&signing_key, b"message2", &k);

        // Verify that r1 == r2
        assert_eq!(r1, r2);

        // Recovers k
        let recovered_k =
            recover_nonce(&hash1, &r1, &s1, &hash2, &r2, &s2).expect("Failed to recover k");
        assert_eq!(k, recovered_k);

        // Recovers d
        let recovered_d = recover_private_key(&recovered_k, &hash1, &r1, &s1);
        let original_d = Scalar::from_repr(signing_key.to_bytes().into()).unwrap();
        assert_eq!(recovered_d, original_d);
    }
}
