use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as KemPublicKeyTrait,
    SharedSecret as SharedSecretTrait,
};
use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::key_schedule::{compute_hmac, verify_hmac};

/// Messages for KEM-TLS handshake
#[derive(Clone)]
pub struct KemClientHello {
    pub nonce_c: Vec<u8>,
    pub kyber_pk_c1: Vec<u8>, // First Kyber public key from client
}

#[derive(Clone)]
pub struct KemServerHello {
    pub nonce_s: Vec<u8>,
    pub kyber_pk_s: Vec<u8>, // Server's Kyber public key (for client to encap)
    pub kyber_ct1: Vec<u8>,  // Ciphertext from encap(pk_c1)
    pub mac_s: Vec<u8>,
}

#[derive(Clone)]
pub struct KemClientFinished {
    pub kyber_ct_s: Vec<u8>, // Ciphertext from encap(pk_s)
    pub mac_c: Vec<u8>,
}

/// KEM-TLS Client
pub struct KemTlsClient {
    // First Kyber keypair (for receiving ct1 from server)
    kyber_pk_c1: kyber768::PublicKey,
    kyber_sk_c1: kyber768::SecretKey,

    // Nonce
    pub nonce: Vec<u8>,

    // Shared secrets
    ss1: Option<Vec<u8>>, // From decap(ct1)
    ss2: Option<Vec<u8>>, // From encap(pk_s)

    // Derived keys
    k2_c: Option<Vec<u8>>,
    k2_s: Option<Vec<u8>>,
    k3_c: Option<Vec<u8>>,
    k3_s: Option<Vec<u8>>,

    // Metrics
    pub handshake_time: Option<std::time::Duration>,
}

impl KemTlsClient {
    pub fn new() -> Self {
        let start = Instant::now();

        // Generate first Kyber keypair
        let (kyber_pk_c1, kyber_sk_c1) = kyber768::keypair();

        // Generate random nonce
        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let setup_time = start.elapsed();

        KemTlsClient {
            kyber_pk_c1,
            kyber_sk_c1,
            nonce,
            ss1: None,
            ss2: None,
            k2_c: None,
            k2_s: None,
            k3_c: None,
            k3_s: None,
            handshake_time: Some(setup_time),
        }
    }

    pub fn send_client_hello(&self) -> KemClientHello {
        KemClientHello {
            nonce_c: self.nonce.clone(),
            kyber_pk_c1: self.kyber_pk_c1.as_bytes().to_vec(),
        }
    }

    pub fn receive_server_hello(
        &mut self,
        server_hello: KemServerHello,
    ) -> Result<KemClientFinished, String> {
        let start = Instant::now();

        let nonce_s = &server_hello.nonce_s;
        let kyber_pk_s = &server_hello.kyber_pk_s;
        let kyber_ct1 = &server_hello.kyber_ct1;
        let mac_s = &server_hello.mac_s;

        // Decapsulate ct1 to get ss1
        let ct1 = kyber768::Ciphertext::from_bytes(kyber_ct1)
            .map_err(|_| "Invalid Kyber ciphertext ct1")?;
        let ss1 = kyber768::decapsulate(&ct1, &self.kyber_sk_c1);
        self.ss1 = Some(ss1.as_bytes().to_vec());

        println!("   ✓ Decapsulated ss1 from ct1");

        // Encapsulate to server's public key to get ss2
        let pk_s = kyber768::PublicKey::from_bytes(kyber_pk_s)
            .map_err(|_| "Invalid server Kyber public key")?;
        let (ss2, ct_s) = kyber768::encapsulate(&pk_s);
        self.ss2 = Some(ss2.as_bytes().to_vec());

        println!("   ✓ Encapsulated ss2 to server");

        // IMPORTANT: For K2 derivation, use ONLY ss1 (server doesn't have ss2 yet)
        // We'll use combined secret only for K3
        let ss1_only = self.ss1.as_ref().unwrap();

        // Derive K2 keys (using only ss1, like the server did)
        let (k2_c, k2_s) = crate::key_schedule::key_schedule_2(
            &self.nonce,
            self.kyber_pk_c1.as_bytes(),
            nonce_s,
            kyber_pk_s,
            ss1_only, // Changed from combined_secret to ss1_only
        );
        self.k2_c = Some(k2_c.clone());
        self.k2_s = Some(k2_s.clone());

        println!("   ✓ K2 keys derived");

        // Verify server MAC
        let mut mac_s_data_hasher = Sha256::new();
        mac_s_data_hasher.update(&self.nonce);
        mac_s_data_hasher.update(self.kyber_pk_c1.as_bytes());
        mac_s_data_hasher.update(nonce_s);
        mac_s_data_hasher.update(kyber_pk_s);
        mac_s_data_hasher.update(kyber_ct1);
        mac_s_data_hasher.update(b"ServerMAC");
        let mac_s_data = mac_s_data_hasher.finalize();

        if !verify_hmac(&k2_s, &mac_s_data, mac_s) {
            return Err("Server MAC verification failed".to_string());
        }

        println!("   ✓ Server MAC verified");

        // Compute client MAC (includes ct_s now)
        let mut mac_c_data_hasher = Sha256::new();
        mac_c_data_hasher.update(&self.nonce);
        mac_c_data_hasher.update(self.kyber_pk_c1.as_bytes());
        mac_c_data_hasher.update(nonce_s);
        mac_c_data_hasher.update(kyber_pk_s);
        mac_c_data_hasher.update(kyber_ct1);
        mac_c_data_hasher.update(ct_s.as_bytes());
        mac_c_data_hasher.update(b"ClientMAC");
        let mac_c_data = mac_c_data_hasher.finalize();
        let mac_c = compute_hmac(&k2_c, &mac_c_data);

        // Derive final K3 keys using COMBINED secret
        let combined_secret = self.combine_secrets();
        let (k3_c, k3_s) = crate::key_schedule::key_schedule_3(
            &self.nonce,
            self.kyber_pk_c1.as_bytes(),
            nonce_s,
            kyber_pk_s,
            &combined_secret, // Now use combined secret for K3
            &[],
            &[],
            mac_s,
        );
        self.k3_c = Some(k3_c);
        self.k3_s = Some(k3_s);

        println!("   ✓ K3 keys derived");

        let elapsed = start.elapsed();
        self.handshake_time = Some(self.handshake_time.unwrap() + elapsed);

        Ok(KemClientFinished {
            kyber_ct_s: ct_s.as_bytes().to_vec(),
            mac_c,
        })
    }

    fn combine_secrets(&self) -> Vec<u8> {
        let ss1 = self.ss1.as_ref().expect("ss1 not set");
        let ss2 = self.ss2.as_ref().expect("ss2 not set");

        // Combine both secrets with hash
        let mut hasher = Sha256::new();
        hasher.update(ss1);
        hasher.update(ss2);
        hasher.finalize().to_vec()
    }

    pub fn get_final_keys(&self) -> Option<(&[u8], &[u8])> {
        if let (Some(k3_c), Some(k3_s)) = (&self.k3_c, &self.k3_s) {
            Some((k3_c, k3_s))
        } else {
            None
        }
    }

    pub fn get_handshake_time(&self) -> Option<std::time::Duration> {
        self.handshake_time
    }
}

/// KEM-TLS Server
pub struct KemTlsServer {
    // Server's Kyber keypair
    kyber_pk_s: kyber768::PublicKey,
    kyber_sk_s: kyber768::SecretKey,

    // Nonce
    pub nonce: Vec<u8>,

    // Shared secrets
    ss1: Option<Vec<u8>>, // From encap(pk_c1)
    ss2: Option<Vec<u8>>, // From decap(ct_s)

    // Derived keys
    k2_c: Option<Vec<u8>>,
    k2_s: Option<Vec<u8>>,
    k3_c: Option<Vec<u8>>,
    k3_s: Option<Vec<u8>>,

    // Metrics
    pub handshake_time: Option<std::time::Duration>,
}

impl KemTlsServer {
    pub fn new() -> Self {
        let start = Instant::now();

        // Generate Kyber keypair
        let (kyber_pk_s, kyber_sk_s) = kyber768::keypair();

        // Generate nonce
        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let setup_time = start.elapsed();

        KemTlsServer {
            kyber_pk_s,
            kyber_sk_s,
            nonce,
            ss1: None,
            ss2: None,
            k2_c: None,
            k2_s: None,
            k3_c: None,
            k3_s: None,
            handshake_time: Some(setup_time),
        }
    }

    pub fn receive_client_hello(
        &mut self,
        client_hello: KemClientHello,
    ) -> Result<KemServerHello, String> {
        let start = Instant::now();

        let nonce_c = &client_hello.nonce_c;
        let kyber_pk_c1_bytes = &client_hello.kyber_pk_c1;

        // Reconstruct client's public key
        let pk_c1 = kyber768::PublicKey::from_bytes(kyber_pk_c1_bytes)
            .map_err(|_| "Invalid client Kyber public key")?;

        // Encapsulate to client's key to get ss1
        let (ss1, ct1) = kyber768::encapsulate(&pk_c1);
        self.ss1 = Some(ss1.as_bytes().to_vec());

        println!("   ✓ Encapsulated ss1 to client");

        // Combine secrets (ss2 will be added later)
        // For now we only have ss1, ss2 will come in ClientFinished

        // Derive K2 keys (using only ss1 for now)
        let combined_secret = ss1.as_bytes().to_vec();

        let (k2_c, k2_s) = crate::key_schedule::key_schedule_2(
            nonce_c,
            kyber_pk_c1_bytes,
            &self.nonce,
            self.kyber_pk_s.as_bytes(),
            &combined_secret,
        );
        self.k2_c = Some(k2_c);
        self.k2_s = Some(k2_s.clone());

        println!("   ✓ K2 keys derived");

        // Compute server MAC
        let mut mac_s_data_hasher = Sha256::new();
        mac_s_data_hasher.update(nonce_c);
        mac_s_data_hasher.update(kyber_pk_c1_bytes);
        mac_s_data_hasher.update(&self.nonce);
        mac_s_data_hasher.update(self.kyber_pk_s.as_bytes());
        mac_s_data_hasher.update(ct1.as_bytes());
        mac_s_data_hasher.update(b"ServerMAC");
        let mac_s_data = mac_s_data_hasher.finalize();
        let mac_s = compute_hmac(&k2_s, &mac_s_data);

        println!("   ✓ Server MAC created");

        let elapsed = start.elapsed();
        self.handshake_time = Some(self.handshake_time.unwrap() + elapsed);

        Ok(KemServerHello {
            nonce_s: self.nonce.clone(),
            kyber_pk_s: self.kyber_pk_s.as_bytes().to_vec(),
            kyber_ct1: ct1.as_bytes().to_vec(),
            mac_s,
        })
    }

    pub fn receive_client_finished(
        &mut self,
        client_finished: KemClientFinished,
        client_hello: &KemClientHello,
        server_hello: &KemServerHello,
    ) -> Result<(), String> {
        let start = Instant::now();

        let kyber_ct_s = &client_finished.kyber_ct_s;

        // Decapsulate ct_s to get ss2
        let ct_s = kyber768::Ciphertext::from_bytes(kyber_ct_s)
            .map_err(|_| "Invalid Kyber ciphertext ct_s")?;
        let ss2 = kyber768::decapsulate(&ct_s, &self.kyber_sk_s);
        self.ss2 = Some(ss2.as_bytes().to_vec());

        println!("   ✓ Decapsulated ss2 from client");

        // Now combine both secrets
        let combined_secret = self.combine_secrets();

        // Re-derive K2 with combined secret? NO - K2 was already used for MACs
        // Only derive K3 with combined secret

        // Verify client MAC (K2_C was derived with ss1 only)
        let k2_c = self.k2_c.as_ref().ok_or("K2_C not derived")?;

        let mut mac_c_data_hasher = Sha256::new();
        mac_c_data_hasher.update(&client_hello.nonce_c);
        mac_c_data_hasher.update(&client_hello.kyber_pk_c1);
        mac_c_data_hasher.update(&server_hello.nonce_s);
        mac_c_data_hasher.update(&server_hello.kyber_pk_s);
        mac_c_data_hasher.update(&server_hello.kyber_ct1);
        mac_c_data_hasher.update(kyber_ct_s);
        mac_c_data_hasher.update(b"ClientMAC");
        let mac_c_data = mac_c_data_hasher.finalize();

        if !verify_hmac(k2_c, &mac_c_data, &client_finished.mac_c) {
            return Err("Client MAC verification failed".to_string());
        }

        println!("   ✓ Client MAC verified");

        // Derive K3 keys with COMBINED secret
        let (k3_c, k3_s) = crate::key_schedule::key_schedule_3(
            &client_hello.nonce_c,
            &client_hello.kyber_pk_c1,
            &server_hello.nonce_s,
            &server_hello.kyber_pk_s,
            &combined_secret, // Use combined secret for K3
            &[],
            &[],
            &server_hello.mac_s,
        );
        self.k3_c = Some(k3_c);
        self.k3_s = Some(k3_s);

        println!("   ✓ K3 keys derived");

        let elapsed = start.elapsed();
        self.handshake_time = Some(self.handshake_time.unwrap() + elapsed);

        Ok(())
    }

    fn combine_secrets(&self) -> Vec<u8> {
        let ss1 = self.ss1.as_ref().expect("ss1 not set");
        let ss2 = self.ss2.as_ref().expect("ss2 not set");

        // Combine both secrets with hash
        let mut hasher = Sha256::new();
        hasher.update(ss1);
        hasher.update(ss2);
        hasher.finalize().to_vec()
    }

    pub fn get_final_keys(&self) -> Option<(&[u8], &[u8])> {
        if let (Some(k3_c), Some(k3_s)) = (&self.k3_c, &self.k3_s) {
            Some((k3_c, k3_s))
        } else {
            None
        }
    }

    pub fn get_handshake_time(&self) -> Option<std::time::Duration> {
        self.handshake_time
    }
}

/// Demonstration of complete KEM-TLS protocol
pub fn demonstrate_kem_tls() {
    println!("\n=== Task 5: KEM-TLS Protocol (Kyber only) ===\n");

    let total_start = Instant::now();

    // 1. Initialization
    println!("1. Initializing KEM-TLS client and server...");
    let mut client = KemTlsClient::new();
    let mut server = KemTlsServer::new();
    println!("   ✓ Client and server initialized\n");

    // 2. ClientHello
    println!("2. Client sends KEM-ClientHello...");
    let client_hello = client.send_client_hello();
    println!(
        "   ✓ KEM-ClientHello sent (nonce: {:02x?}...)\n",
        &client_hello.nonce_c[..4]
    );

    // 3. ServerHello
    println!("3. Server processes and sends KEM-ServerHello...");
    let server_hello = match server.receive_client_hello(client_hello.clone()) {
        Ok(sh) => {
            println!("   ✓ KEM-ServerHello created\n");
            sh
        }
        Err(e) => {
            println!("   ✗ Error: {}\n", e);
            return;
        }
    };

    // 4. ClientFinished
    println!("4. Client processes KEM-ServerHello...");
    let client_finished = match client.receive_server_hello(server_hello.clone()) {
        Ok(cf) => {
            println!("   ✓ KEM-ClientFinished created\n");
            cf
        }
        Err(e) => {
            println!("   ✗ Error: {}\n", e);
            return;
        }
    };

    // 5. Server finalizes
    println!("5. Server processes KEM-ClientFinished...");
    match server.receive_client_finished(client_finished, &client_hello, &server_hello) {
        Ok(_) => println!("   ✓ KEM-TLS handshake completed successfully\n"),
        Err(e) => {
            println!("   ✗ Error: {}\n", e);
            return;
        }
    }

    // 6. Verify final keys
    println!("6. Verifying final keys (K3)...");
    let client_keys = client.get_final_keys().expect("Client keys not derived");
    let server_keys = server.get_final_keys().expect("Server keys not derived");

    if client_keys.0 == server_keys.0 && client_keys.1 == server_keys.1 {
        println!("   ✓ K3 keys match!");
        println!("   K3_C (first 16 bytes): {:02x?}", &client_keys.0[..16]);
        println!("   K3_S (first 16 bytes): {:02x?}", &client_keys.1[..16]);
    } else {
        println!("   ✗ ERROR: Keys do not match!");
    }

    let total_time = total_start.elapsed();
    println!("\n7. Performance metrics:");
    println!("   - Total handshake time: {:?}", total_time);
    println!(
        "   - Client time: {:?}",
        client.get_handshake_time().unwrap()
    );
    println!(
        "   - Server time: {:?}",
        server.get_handshake_time().unwrap()
    );

    println!("\n=== KEM-TLS handshake completed successfully! ===\n");
}
