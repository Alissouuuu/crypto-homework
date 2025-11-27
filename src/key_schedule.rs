use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Derive Handshake secret from the DH shared secret
/// DeriveHS(g^xy):
/// 1. ES = HKDF.Extract(0, 0)
/// 2. dES = HKDF.Expand(ES, SHA256("DerivedES"))
/// 3. HS = HKDF.Extract(dES, SHA256(g^xy))
/// 4. return HS
pub fn derive_hs(shared_secret: &[u8]) -> Vec<u8> {
    // 1. ES = HKDF.Extract(0, 0)
    let zeros = [0u8; 32];
    let es = Hkdf::<Sha256>::new(Some(&zeros), &zeros);

    // 2. dES = HKDF.Expand(ES, SHA256("DerivedES"))
    let derived_es_label = Sha256::digest(b"DerivedES");
    let mut des = [0u8; 32];
    es.expand(&derived_es_label, &mut des)
        .expect("HKDF expand failed");

    // 3. HS = HKDF.Extract(dES, SHA256(g^xy))
    let shared_secret_hash = Sha256::digest(shared_secret);
    let hs = Hkdf::<Sha256>::new(Some(&des), &shared_secret_hash);

    // 4. return HS (As PRK bytes)
    // On doit extraire les bytes du PRK
    // We should extract bytes from PRK
    let mut hs_bytes = [0u8; 32];
    hs.expand(&[], &mut hs_bytes).expect("HKDF expand failed");
    hs_bytes.to_vec()
}

/// KeySchedule1(g^xy):
/// 1. HS = DeriveHS(g^xy)
/// 2. K1_C = HKDF.Expand(HS, SHA256("ClientKE"))
/// 3. K1_S = HKDF.Expand(HS, SHA256("ServerKE"))
/// 4. return K1_C, K1_S
pub fn key_schedule_1(shared_secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // 1. HS = DeriveHS(g^xy)
    let hs_vec = derive_hs(shared_secret);
    let hs = Hkdf::<Sha256>::from_prk(&hs_vec).expect("Invalid PRK length");

    // 2. K1_C = HKDF.Expand(HS, SHA256("ClientKE"))
    let client_ke_label = Sha256::digest(b"ClientKE");
    let mut k1_c = [0u8; 32];
    hs.expand(&client_ke_label, &mut k1_c)
        .expect("HKDF expand failed");

    // 3. K1_S = HKDF.Expand(HS, SHA256("ServerKE"))
    let server_ke_label = Sha256::digest(b"ServerKE");
    let mut k1_s = [0u8; 32];
    hs.expand(&server_ke_label, &mut k1_s)
        .expect("HKDF expand failed");

    // 4. return K1_C, K1_S
    (k1_c.to_vec(), k1_s.to_vec())
}

/// KeySchedule2(nonce_C, X, nonce_S, Y, g^xy):
/// 1. HS = DeriveHS(g^xy)
/// 2. ClientKC = SHA256(nonce_C || X || nonce_S || Y || "ClientKC")
/// 3. ServerKC = SHA256(nonce_C || X || nonce_S || Y || "ServerKC")
/// 4. K2_C = HKDF.Expand(HS, ClientKC)
/// 5. K2_S = HKDF.Expand(HS, ServerKC)
/// 6. return K2_C, K2_S
pub fn key_schedule_2(
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    shared_secret: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // 1. HS = DeriveHS(g^xy)
    let hs_vec = derive_hs(shared_secret);
    let hs = Hkdf::<Sha256>::from_prk(&hs_vec).expect("Invalid PRK length");

    // 2. ClientKC = SHA256(nonce_C || X || nonce_S || Y || "ClientKC")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(b"ClientKC");
    let client_kc = hasher.finalize();

    // 3. ServerKC = SHA256(nonce_C || X || nonce_S || Y || "ServerKC")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(b"ServerKC");
    let server_kc = hasher.finalize();

    // 4. K2_C = HKDF.Expand(HS, ClientKC)
    let mut k2_c = [0u8; 32];
    hs.expand(&client_kc, &mut k2_c)
        .expect("HKDF expand failed");

    // 5. K2_S = HKDF.Expand(HS, ServerKC)
    let mut k2_s = [0u8; 32];
    hs.expand(&server_kc, &mut k2_s)
        .expect("HKDF expand failed");

    // 6. return K2_C, K2_S
    (k2_c.to_vec(), k2_s.to_vec())
}

/// KeySchedule3(nonce_C, X, nonce_S, Y, g^xy, σ, cert_pk_S, mac_S):
/// 1. HS = DeriveHS(g^xy)
/// 2. dHS = HKDF.Expand(HS, SHA256("DerivedHS"))
/// 3. MS = HKDF.Extract(dHS, 0)
/// 4. ClientSKH = SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || mac_S || "ClientEncK")
/// 5. ServerSKH = SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || mac_S || "ServerEncK")
/// 6. K3_C = HKDF.Expand(MS, ClientSKH)
/// 7. K3_S = HKDF.Expand(MS, ServerSKH)
/// 8. return K3_C, K3_S
pub fn key_schedule_3(
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    shared_secret: &[u8],
    sigma: &[u8],
    cert_pk_s: &[u8],
    mac_s: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // 1. HS = DeriveHS(g^xy)
    let hs_vec = derive_hs(shared_secret);
    let hs = Hkdf::<Sha256>::from_prk(&hs_vec).expect("Invalid PRK length");

    // 2. dHS = HKDF.Expand(HS, SHA256("DerivedHS"))
    let derived_hs_label = Sha256::digest(b"DerivedHS");
    let mut dhs = [0u8; 32];
    hs.expand(&derived_hs_label, &mut dhs)
        .expect("HKDF expand failed");

    // 3. MS = HKDF.Extract(dHS, 0)
    let zeros = [0u8; 32];
    let ms = Hkdf::<Sha256>::new(Some(&dhs), &zeros);

    // 4. ClientSKH = SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || mac_S || "ClientEncK")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(sigma);
    hasher.update(cert_pk_s);
    hasher.update(mac_s);
    hasher.update(b"ClientEncK");
    let client_skh = hasher.finalize();

    // 5. ServerSKH = SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || mac_S || "ServerEncK")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(sigma);
    hasher.update(cert_pk_s);
    hasher.update(mac_s);
    hasher.update(b"ServerEncK");
    let server_skh = hasher.finalize();

    // 6. K3_C = HKDF.Expand(MS, ClientSKH)
    let mut k3_c = [0u8; 32];
    ms.expand(&client_skh, &mut k3_c)
        .expect("HKDF expand failed");

    // 7. K3_S = HKDF.Expand(MS, ServerSKH)
    let mut k3_s = [0u8; 32];
    ms.expand(&server_skh, &mut k3_s)
        .expect("HKDF expand failed");

    // 8. return K3_C, K3_S
    (k3_c.to_vec(), k3_s.to_vec())
}

/// Calculate a HMAC-SHA256
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Vertify a HMAC-SHA256
pub fn verify_hmac(key: &[u8], data: &[u8], expected_mac: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(expected_mac).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_hs() {
        let shared_secret = b"test_shared_secret";
        let hs = derive_hs(shared_secret);
        assert_eq!(hs.len(), 32);
    }

    #[test]
    fn test_key_schedule_1() {
        let shared_secret = b"test_shared_secret";
        let (k1_c, k1_s) = key_schedule_1(shared_secret);

        assert_eq!(k1_c.len(), 32);
        assert_eq!(k1_s.len(), 32);
        assert_ne!(k1_c, k1_s); // Keys must be different
    }

    #[test]
    fn test_key_schedule_2() {
        let nonce_c = b"client_nonce";
        let x = b"client_public_key";
        let nonce_s = b"server_nonce";
        let y = b"server_public_key";
        let shared_secret = b"shared_secret";

        let (k2_c, k2_s) = key_schedule_2(nonce_c, x, nonce_s, y, shared_secret);

        assert_eq!(k2_c.len(), 32);
        assert_eq!(k2_s.len(), 32);
        assert_ne!(k2_c, k2_s);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret_key";
        let data = b"hello world";

        let mac = compute_hmac(key, data);
        assert_eq!(mac.len(), 32);

        // Positive verification
        assert!(verify_hmac(key, data, &mac));

        // Negative verification (wrong key)
        assert!(!verify_hmac(b"wrong_key", data, &mac));

        // Vérification négative (mauvaises données)
        // Negative verification (wrong datas)
        assert!(!verify_hmac(key, b"wrong data", &mac));
    }
}
