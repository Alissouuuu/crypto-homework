use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKey,
    SharedSecret,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as SigPublicKeyTrait,
    SecretKey as SigSecretKey,
};
use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::key_schedule::{compute_hmac, verify_hmac};

/// Test simple : génération de clés Kyber et Dilithium
pub fn test_pq_primitives() {
    println!("\n=== Test des primitives Post-Quantiques ===\n");

    // Test Kyber (KEM)
    println!("1. Test Kyber768 (KEM)...");
    let (kyber_pk, kyber_sk) = kyber768::keypair();
    println!("   ✓ Clés Kyber générées");
    println!(
        "   - Taille clé publique : {} bytes",
        kyber_pk.as_bytes().len()
    );
    println!(
        "   - Taille clé privée : {} bytes",
        kyber_sk.as_bytes().len()
    );

    // Encapsulation
    let (shared_secret_enc, ciphertext) = kyber768::encapsulate(&kyber_pk);
    println!("   ✓ Secret encapsulé");
    println!(
        "   - Taille ciphertext : {} bytes",
        ciphertext.as_bytes().len()
    );
    println!(
        "   - Taille secret partagé : {} bytes",
        shared_secret_enc.as_bytes().len()
    );

    // Décapsulation
    let shared_secret_dec = kyber768::decapsulate(&ciphertext, &kyber_sk);
    println!("   ✓ Secret décapsulé");

    // Vérification
    if shared_secret_enc.as_bytes() == shared_secret_dec.as_bytes() {
        println!("   ✓ Secrets identiques : Kyber fonctionne !\n");
    } else {
        println!("   ✗ ERREUR : Secrets différents\n");
        return;
    }

    // Test Dilithium (Signatures)
    println!("2. Test Dilithium3 (Signatures)...");
    let (dilithium_pk, dilithium_sk) = dilithium3::keypair();
    println!("   ✓ Clés Dilithium générées");
    println!(
        "   - Taille clé publique : {} bytes",
        dilithium_pk.as_bytes().len()
    );
    println!(
        "   - Taille clé privée : {} bytes",
        dilithium_sk.as_bytes().len()
    );

    // Signature
    let message = b"Hello, Post-Quantum World!";
    let signature = dilithium3::detached_sign(message, &dilithium_sk);
    println!("   ✓ Message signé");
    println!(
        "   - Taille signature : {} bytes",
        signature.as_bytes().len()
    );

    // Vérification
    match dilithium3::verify_detached_signature(&signature, message, &dilithium_pk) {
        Ok(_) => println!("   ✓ Signature vérifiée : Dilithium fonctionne !\n"),
        Err(_) => {
            println!("   ✗ ERREUR : Vérification échouée\n");
            return;
        }
    }

    println!("=== Tous les tests passent ! ===\n");
}

/// Messages pour PQ-TLS handshake
#[derive(Clone)]
pub struct PqClientHello {
    pub nonce_c: Vec<u8>,
    pub kyber_pk_c: Vec<u8>, // Clé publique Kyber du client
}

#[derive(Clone)]
pub struct PqServerHello {
    pub nonce_s: Vec<u8>,
    pub kyber_ct: Vec<u8>,       // Ciphertext Kyber (encapsulation du secret)
    pub dilithium_pk_s: Vec<u8>, // Clé publique Dilithium du serveur
    pub signature: Vec<u8>,      // Signature Dilithium
    pub mac_s: Vec<u8>,          // MAC du serveur
}

#[derive(Clone)]
pub struct PqClientFinished {
    pub mac_c: Vec<u8>,
}

/// Client PQ-TLS
pub struct PqTlsClient {
    // Kyber KEM
    kyber_pk: kyber768::PublicKey,
    kyber_sk: kyber768::SecretKey,

    // Nonce
    pub nonce: Vec<u8>,

    // Secret partagé (après handshake)
    shared_secret: Option<Vec<u8>>,

    // Clés dérivées
    k2_c: Option<Vec<u8>>,
    k2_s: Option<Vec<u8>>,
    k3_c: Option<Vec<u8>>,
    k3_s: Option<Vec<u8>>,

    // Métriques de temps
    pub handshake_time: Option<std::time::Duration>,
}

impl PqTlsClient {
    pub fn new() -> Self {
        let start = Instant::now();

        // Génère paire de clés Kyber
        let (kyber_pk, kyber_sk) = kyber768::keypair();

        // Génère nonce aléatoire
        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let setup_time = start.elapsed();

        PqTlsClient {
            kyber_pk,
            kyber_sk,
            nonce,
            shared_secret: None,
            k2_c: None,
            k2_s: None,
            k3_c: None,
            k3_s: None,
            handshake_time: Some(setup_time),
        }
    }

    pub fn send_client_hello(&self) -> PqClientHello {
        PqClientHello {
            nonce_c: self.nonce.clone(),
            kyber_pk_c: self.kyber_pk.as_bytes().to_vec(),
        }
    }

    pub fn receive_server_hello(
        &mut self,
        server_hello: PqServerHello,
    ) -> Result<PqClientFinished, String> {
        let start = Instant::now();

        let nonce_s = &server_hello.nonce_s;
        let kyber_ct = &server_hello.kyber_ct;
        let dilithium_pk_s = &server_hello.dilithium_pk_s;
        let signature = &server_hello.signature;
        let mac_s = &server_hello.mac_s;

        // Reconstruct Dilithium public key
        let server_vk = dilithium3::PublicKey::from_bytes(dilithium_pk_s)
            .map_err(|_| "Invalid Dilithium public key")?;

        // Verify signature
        let mut sig_data_hasher = Sha256::new();
        sig_data_hasher.update(&self.nonce);
        sig_data_hasher.update(self.kyber_pk.as_bytes());
        sig_data_hasher.update(nonce_s);
        sig_data_hasher.update(kyber_ct);
        sig_data_hasher.update(dilithium_pk_s);
        let sig_data = sig_data_hasher.finalize();

        let sig = dilithium3::DetachedSignature::from_bytes(signature)
            .map_err(|_| "Invalid signature format")?;

        dilithium3::verify_detached_signature(&sig, &sig_data, &server_vk)
            .map_err(|_| "Signature verification failed")?;

        println!("   ✓ Dilithium signature verified");

        // Decapsulate Kyber secret
        let ct =
            kyber768::Ciphertext::from_bytes(kyber_ct).map_err(|_| "Invalid Kyber ciphertext")?;
        let ss = kyber768::decapsulate(&ct, &self.kyber_sk);
        self.shared_secret = Some(ss.as_bytes().to_vec());

        println!("   ✓ Kyber secret decapsulated");

        // Dérive les clés K2 (réutilise key_schedule_2 de task2)
        let shared_secret = self.shared_secret.as_ref().unwrap();
        let (k2_c, k2_s) = crate::key_schedule::key_schedule_2(
            &self.nonce,
            self.kyber_pk.as_bytes(),
            nonce_s,
            kyber_ct,
            shared_secret,
        );
        self.k2_c = Some(k2_c.clone());
        self.k2_s = Some(k2_s.clone());

        println!("   ✓ Clés K2 dérivées");

        // Vérifie mac_S
        let mut mac_s_data_hasher = Sha256::new();
        mac_s_data_hasher.update(&self.nonce);
        mac_s_data_hasher.update(self.kyber_pk.as_bytes());
        mac_s_data_hasher.update(nonce_s);
        mac_s_data_hasher.update(kyber_ct);
        mac_s_data_hasher.update(signature);
        mac_s_data_hasher.update(dilithium_pk_s);
        mac_s_data_hasher.update(b"ServerMAC");
        let mac_s_data = mac_s_data_hasher.finalize();

        if !verify_hmac(&k2_s, &mac_s_data, mac_s) {
            return Err("Server MAC verification failed".to_string());
        }

        println!("   ✓ MAC serveur vérifié");

        // Calcule mac_C
        let mut mac_c_data_hasher = Sha256::new();
        mac_c_data_hasher.update(&self.nonce);
        mac_c_data_hasher.update(self.kyber_pk.as_bytes());
        mac_c_data_hasher.update(nonce_s);
        mac_c_data_hasher.update(kyber_ct);
        mac_c_data_hasher.update(signature);
        mac_c_data_hasher.update(dilithium_pk_s);
        mac_c_data_hasher.update(b"ClientMAC");
        let mac_c_data = mac_c_data_hasher.finalize();
        let mac_c = compute_hmac(&k2_c, &mac_c_data);

        // Dérive clés finales K3
        let (k3_c, k3_s) = crate::key_schedule::key_schedule_3(
            &self.nonce,
            self.kyber_pk.as_bytes(),
            nonce_s,
            kyber_ct,
            shared_secret,
            signature,
            dilithium_pk_s,
            mac_s,
        );
        self.k3_c = Some(k3_c);
        self.k3_s = Some(k3_s);

        println!("   ✓ Clés K3 dérivées");

        let elapsed = start.elapsed();
        self.handshake_time = Some(self.handshake_time.unwrap() + elapsed);

        Ok(PqClientFinished { mac_c })
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

/// Serveur PQ-TLS
pub struct PqTlsServer {
    // Dilithium pour signatures
    dilithium_pk: dilithium3::PublicKey,
    dilithium_sk: dilithium3::SecretKey,

    // Nonce
    pub nonce: Vec<u8>,

    // Secret partagé (après encapsulation Kyber)
    shared_secret: Option<Vec<u8>>,

    // Clés dérivées
    k2_c: Option<Vec<u8>>,
    k2_s: Option<Vec<u8>>,
    k3_c: Option<Vec<u8>>,
    k3_s: Option<Vec<u8>>,

    // Métriques
    pub handshake_time: Option<std::time::Duration>,
}

impl PqTlsServer {
    pub fn new() -> Self {
        let start = Instant::now();

        // Génère paire de clés Dilithium
        let (dilithium_pk, dilithium_sk) = dilithium3::keypair();

        // Génère nonce
        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let setup_time = start.elapsed();

        PqTlsServer {
            dilithium_pk,
            dilithium_sk,
            nonce,
            shared_secret: None,
            k2_c: None,
            k2_s: None,
            k3_c: None,
            k3_s: None,
            handshake_time: Some(setup_time),
        }
    }

    pub fn receive_client_hello(
        &mut self,
        client_hello: PqClientHello,
    ) -> Result<PqServerHello, String> {
        let start = Instant::now();

        let nonce_c = &client_hello.nonce_c;
        let kyber_pk_c_bytes = &client_hello.kyber_pk_c;

        // Reconstruct client's Kyber public key
        let client_pk = kyber768::PublicKey::from_bytes(kyber_pk_c_bytes)
            .map_err(|_| "Invalid Kyber public key")?;

        // Encapsulate secret with Kyber
        let (ss, ct) = kyber768::encapsulate(&client_pk);
        self.shared_secret = Some(ss.as_bytes().to_vec());

        println!("   ✓ Kyber secret encapsulated");

        // Dérive clés K2
        let shared_secret = self.shared_secret.as_ref().unwrap();
        let kyber_ct_bytes = ct.as_bytes();

        let (k2_c, k2_s) = crate::key_schedule::key_schedule_2(
            nonce_c,
            kyber_pk_c_bytes,
            &self.nonce,
            kyber_ct_bytes,
            shared_secret,
        );
        self.k2_c = Some(k2_c);
        self.k2_s = Some(k2_s.clone());

        println!("   ✓ Clés K2 dérivées");

        // Signe avec Dilithium
        let mut sig_data_hasher = Sha256::new();
        sig_data_hasher.update(nonce_c);
        sig_data_hasher.update(kyber_pk_c_bytes);
        sig_data_hasher.update(&self.nonce);
        sig_data_hasher.update(kyber_ct_bytes);
        sig_data_hasher.update(self.dilithium_pk.as_bytes());
        let sig_data = sig_data_hasher.finalize();

        let signature = dilithium3::detached_sign(&sig_data, &self.dilithium_sk);

        println!("   ✓ Signature Dilithium créée");

        // Calcule MAC
        let mut mac_s_data_hasher = Sha256::new();
        mac_s_data_hasher.update(nonce_c);
        mac_s_data_hasher.update(kyber_pk_c_bytes);
        mac_s_data_hasher.update(&self.nonce);
        mac_s_data_hasher.update(kyber_ct_bytes);
        mac_s_data_hasher.update(signature.as_bytes());
        mac_s_data_hasher.update(self.dilithium_pk.as_bytes());
        mac_s_data_hasher.update(b"ServerMAC");
        let mac_s_data = mac_s_data_hasher.finalize();
        let mac_s = compute_hmac(&k2_s, &mac_s_data);

        println!("   ✓ MAC serveur créé");

        let elapsed = start.elapsed();
        self.handshake_time = Some(self.handshake_time.unwrap() + elapsed);

        Ok(PqServerHello {
            nonce_s: self.nonce.clone(),
            kyber_ct: kyber_ct_bytes.to_vec(),
            dilithium_pk_s: self.dilithium_pk.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
            mac_s,
        })
    }

    pub fn receive_client_finished(
        &mut self,
        client_finished: PqClientFinished,
        client_hello: &PqClientHello,
        server_hello: &PqServerHello,
    ) -> Result<(), String> {
        let start = Instant::now();

        let k2_c = self.k2_c.as_ref().ok_or("K2_C not derived")?;

        // Vérifie mac_C
        let mut mac_c_data_hasher = Sha256::new();
        mac_c_data_hasher.update(&client_hello.nonce_c);
        mac_c_data_hasher.update(&client_hello.kyber_pk_c);
        mac_c_data_hasher.update(&server_hello.nonce_s);
        mac_c_data_hasher.update(&server_hello.kyber_ct);
        mac_c_data_hasher.update(&server_hello.signature);
        mac_c_data_hasher.update(&server_hello.dilithium_pk_s);
        mac_c_data_hasher.update(b"ClientMAC");
        let mac_c_data = mac_c_data_hasher.finalize();

        if !verify_hmac(k2_c, &mac_c_data, &client_finished.mac_c) {
            return Err("Client MAC verification failed".to_string());
        }

        println!("   ✓ MAC client vérifié");

        // Dérive K3
        let shared_secret = self.shared_secret.as_ref().unwrap();
        let (k3_c, k3_s) = crate::key_schedule::key_schedule_3(
            &client_hello.nonce_c,
            &client_hello.kyber_pk_c,
            &server_hello.nonce_s,
            &server_hello.kyber_ct,
            shared_secret,
            &server_hello.signature,
            &server_hello.dilithium_pk_s,
            &server_hello.mac_s,
        );
        self.k3_c = Some(k3_c);
        self.k3_s = Some(k3_s);

        println!("   ✓ Clés K3 dérivées");

        let elapsed = start.elapsed();
        self.handshake_time = Some(self.handshake_time.unwrap() + elapsed);

        Ok(())
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

/// Démonstration du protocole PQ-TLS complet
pub fn demonstrate_pq_tls() {
    println!("\n=== Task 4: PQ-TLS Protocol (Kyber + Dilithium) ===\n");

    let total_start = Instant::now();

    // 1. Initialisation
    println!("1. Initialisation du client et du serveur PQ...");
    let mut client = PqTlsClient::new();
    let mut server = PqTlsServer::new();
    println!("   ✓ Client et serveur initialisés\n");

    // 2. ClientHello
    println!("2. Client envoie PQ-ClientHello...");
    let client_hello = client.send_client_hello();
    println!(
        "   ✓ PQ-ClientHello envoyé (nonce: {:02x?}...)\n",
        &client_hello.nonce_c[..4]
    );

    // 3. ServerHello
    println!("3. Serveur traite et envoie PQ-ServerHello...");
    let server_hello = match server.receive_client_hello(client_hello.clone()) {
        Ok(sh) => {
            println!("   ✓ PQ-ServerHello créé\n");
            sh
        }
        Err(e) => {
            println!("   ✗ Erreur: {}\n", e);
            return;
        }
    };

    // 4. ClientFinished
    println!("4. Client traite PQ-ServerHello...");
    let client_finished = match client.receive_server_hello(server_hello.clone()) {
        Ok(cf) => {
            println!("   ✓ PQ-ClientFinished créé\n");
            cf
        }
        Err(e) => {
            println!("   ✗ Erreur: {}\n", e);
            return;
        }
    };

    // 5. Serveur finalise
    println!("5. Serveur traite PQ-ClientFinished...");
    match server.receive_client_finished(client_finished, &client_hello, &server_hello) {
        Ok(_) => println!("   ✓ Handshake PQ-TLS terminé avec succès\n"),
        Err(e) => {
            println!("   ✗ Erreur: {}\n", e);
            return;
        }
    }

    // 6. Vérification des clés finales
    println!("6. Vérification des clés finales (K3)...");
    let client_keys = client.get_final_keys().expect("Client keys not derived");
    let server_keys = server.get_final_keys().expect("Server keys not derived");

    if client_keys.0 == server_keys.0 && client_keys.1 == server_keys.1 {
        println!("   ✓ Les clés K3 correspondent!");
        println!("   K3_C (premiers 16 bytes): {:02x?}", &client_keys.0[..16]);
        println!("   K3_S (premiers 16 bytes): {:02x?}", &client_keys.1[..16]);
    } else {
        println!("   ✗ ERREUR: Les clés ne correspondent pas!");
    }

    let total_time = total_start.elapsed();
    println!("\n7. Métriques de performance:");
    println!("   - Temps total handshake: {:?}", total_time);
    println!(
        "   - Temps client: {:?}",
        client.get_handshake_time().unwrap()
    );
    println!(
        "   - Temps serveur: {:?}",
        server.get_handshake_time().unwrap()
    );

    println!("\n=== Handshake PQ-TLS terminé avec succès! ===\n");
}
