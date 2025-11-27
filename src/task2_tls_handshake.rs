use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::{ecdh::EphemeralSecret, PublicKey as DhPublicKey};
use sha2::{Digest, Sha256};

use crate::key_schedule::{
    compute_hmac, key_schedule_1, key_schedule_2, key_schedule_3, verify_hmac,
};

/// Exchanged messages while handshake TLS
#[derive(Clone)]
pub struct ClientHello {
    pub nonce_c: Vec<u8>,
    pub x: DhPublicKey, // DH public key of the client
}

#[derive(Clone)]
pub struct ServerHello {
    pub nonce_s: Vec<u8>,
    pub y: DhPublicKey,     // DH public key of the server
    pub sigma: Vec<u8>,     // Server signature (in bytes to enable cloning)
    pub cert_pk_s: Vec<u8>, // Certificate (public signing key)
    pub mac_s: Vec<u8>,     // MAC address of the server
}

pub struct ClientFinished {
    pub mac_c: Vec<u8>, // MAC address of the client
}

/// Represent TLS client
pub struct TlsClient {
    // Ephemeral DH key
    dh_secret: Option<EphemeralSecret>,
    pub dh_public: DhPublicKey,

    // Nonce
    pub nonce: Vec<u8>,

    // Derived keys (stored after handshake)
    k1_c: Option<Vec<u8>>,
    k1_s: Option<Vec<u8>>,
    k2_c: Option<Vec<u8>>,
    k2_s: Option<Vec<u8>>,
    k3_c: Option<Vec<u8>>,
    k3_s: Option<Vec<u8>>,
}

impl TlsClient {
    /// Create a nex TLS client
    pub fn new() -> Self {
        let mut rng = p256::elliptic_curve::rand_core::OsRng;

        // Generates ephemeral DH key
        let dh_secret = EphemeralSecret::random(&mut rng);
        let dh_public = DhPublicKey::from(&dh_secret);

        // Generates random nonce (32 bytes)
        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        TlsClient {
            dh_secret: Some(dh_secret),
            dh_public,
            nonce,
            k1_c: None,
            k1_s: None,
            k2_c: None,
            k2_s: None,
            k3_c: None,
            k3_s: None,
        }
    }

    /// Step 1: Send ClientHello
    pub fn send_client_hello(&self) -> ClientHello {
        ClientHello {
            nonce_c: self.nonce.clone(),
            x: self.dh_public.clone(),
        }
    }

    /// Step 2: Receive ServerHello and verify
    pub fn receive_server_hello(
        &mut self,
        server_hello: ServerHello,
    ) -> Result<ClientFinished, String> {
        // Extract datas
        let nonce_s = &server_hello.nonce_s;
        let y = &server_hello.y;
        let sigma_bytes = &server_hello.sigma;
        let cert_pk_s = &server_hello.cert_pk_s;
        let mac_s = &server_hello.mac_s;

        // Reconstructs the server's verification key
        let verifying_key =
            VerifyingKey::from_sec1_bytes(cert_pk_s).map_err(|_| "Invalid server certificate")?;

        // Reconstructs the signature from the bytes
        let sigma = Signature::from_bytes(sigma_bytes.as_slice().into())
            .map_err(|_| "Invalid signature format")?;

        // Verify the signature σ
        // σ = Sign(sk_S, SHA256(nonce_C || X || nonce_S || Y || cert_pk_S))
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(self.dh_public.to_sec1_bytes());
        hasher.update(nonce_s);
        hasher.update(y.to_sec1_bytes());
        hasher.update(cert_pk_s);
        let sig_data = hasher.finalize();

        verifying_key
            .verify(&sig_data, &sigma)
            .map_err(|_| "Server signature verification failed")?;

        println!("-> Signature of the server verified !");

        // Calculate the shared secret g^xy
        let dh_secret = self.dh_secret.take().ok_or("DH secret already consumed")?;
        let shared_secret_point = dh_secret.diffie_hellman(y);
        let shared_secret = shared_secret_point.raw_secret_bytes();

        // KeySchedule1: Derive K1_C and K1_S
        let (k1_c, k1_s) = key_schedule_1(shared_secret.as_slice());
        self.k1_c = Some(k1_c.clone());
        self.k1_s = Some(k1_s.clone());

        println!("-> KeySchedule1 calculated !");

        // KeySchedule2: Derive K2_C and K2_S
        let x_bytes = self.dh_public.to_sec1_bytes();
        let y_bytes = y.to_sec1_bytes();
        let (k2_c, k2_s) = key_schedule_2(
            &self.nonce,
            &x_bytes,
            nonce_s,
            &y_bytes,
            shared_secret.as_slice(),
        );
        self.k2_c = Some(k2_c.clone());
        self.k2_s = Some(k2_s.clone());

        println!("-> KeySchedule2 calculated !");

        // Verify mac_S
        // mac_S = HMAC(K2_S, SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || "ServerMAC"))
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(&x_bytes);
        hasher.update(nonce_s);
        hasher.update(&y_bytes);
        hasher.update(sigma_bytes);
        hasher.update(cert_pk_s);
        hasher.update(b"ServerMAC");
        let mac_s_data = hasher.finalize();

        if !verify_hmac(&k2_s, &mac_s_data, mac_s) {
            return Err("Server MAC verification failed".to_string());
        }

        println!("-> MAC adress of the server verified !");

        // Calculate mac_C
        // mac_C = HMAC(K2_C, SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || "ClientMAC"))
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(&x_bytes);
        hasher.update(nonce_s);
        hasher.update(&y_bytes);
        hasher.update(sigma_bytes);
        hasher.update(cert_pk_s);
        hasher.update(b"ClientMAC");
        let mac_c_data = hasher.finalize();
        let mac_c = compute_hmac(&k2_c, &mac_c_data);

        // KeySchedule3: Derive K3_C and K3_S
        let (k3_c, k3_s) = key_schedule_3(
            &self.nonce,
            &x_bytes,
            nonce_s,
            &y_bytes,
            shared_secret.as_slice(),
            sigma_bytes,
            cert_pk_s,
            mac_s,
        );
        self.k3_c = Some(k3_c);
        self.k3_s = Some(k3_s);

        println!("-> KeySchedule3 calculated");

        Ok(ClientFinished { mac_c })
    }

    /// Récupère les clés finales K3
    pub fn get_final_keys(&self) -> Option<(&[u8], &[u8])> {
        if let (Some(k3_c), Some(k3_s)) = (&self.k3_c, &self.k3_s) {
            Some((k3_c, k3_s))
        } else {
            None
        }
    }
}

/// Represent the TLS server
pub struct TlsServer {
    // Signature keys
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,

    // DH ephemeral key
    dh_secret: Option<EphemeralSecret>,
    pub dh_public: DhPublicKey,

    // Nonce
    pub nonce: Vec<u8>,

    // Shared secret (stored after ClientHello)
    shared_secret: Option<Vec<u8>>,

    // Derived keys
    k1_c: Option<Vec<u8>>,
    k1_s: Option<Vec<u8>>,
    k2_c: Option<Vec<u8>>,
    k2_s: Option<Vec<u8>>,
    k3_c: Option<Vec<u8>>,
    k3_s: Option<Vec<u8>>,
}

impl TlsServer {
    /// Create a new TLS server
    pub fn new() -> Self {
        let mut rng = p256::elliptic_curve::rand_core::OsRng;

        // Generates a pair of signature keys
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Generates ephemeral DH key
        let dh_secret = EphemeralSecret::random(&mut rng);
        let dh_public = DhPublicKey::from(&dh_secret);

        // Generates random nonce
        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        TlsServer {
            signing_key,
            verifying_key,
            dh_secret: Some(dh_secret),
            dh_public,
            nonce,
            shared_secret: None,
            k1_c: None,
            k1_s: None,
            k2_c: None,
            k2_s: None,
            k3_c: None,
            k3_s: None,
        }
    }

    /// Step 1: Receives ClientHello and responds with ServerHello
    pub fn receive_client_hello(
        &mut self,
        client_hello: ClientHello,
    ) -> Result<ServerHello, String> {
        let nonce_c = &client_hello.nonce_c;
        let x = &client_hello.x;

        // Calculate the shared secret g^xy
        let dh_secret = self.dh_secret.take().ok_or("DH secret already consumed")?;
        let shared_secret_point = dh_secret.diffie_hellman(x);
        let shared_secret = shared_secret_point.raw_secret_bytes().to_vec();

        // Stores the shared secret for KeySchedule3 later
        self.shared_secret = Some(shared_secret.clone());

        // KeySchedule1
        let (k1_c, k1_s) = key_schedule_1(shared_secret.as_slice());
        self.k1_c = Some(k1_c);
        self.k1_s = Some(k1_s);

        println!("-> KeySchedule1 calculated !");

        // KeySchedule2
        let x_bytes = x.to_sec1_bytes();
        let y_bytes = self.dh_public.to_sec1_bytes();
        let (k2_c, k2_s) = key_schedule_2(
            nonce_c,
            &x_bytes,
            &self.nonce,
            &y_bytes,
            shared_secret.as_slice(),
        );
        self.k2_c = Some(k2_c);
        self.k2_s = Some(k2_s.clone());

        println!("-> KeySchedule2 calculated !");

        // Certificate (public signing key)
        let cert_pk_s = self.verifying_key.to_sec1_bytes().to_vec();

        // Calculate the signature σ
        // σ = Sign(sk_S, SHA256(nonce_C || X || nonce_S || Y || cert_pk_S))
        let mut hasher = Sha256::new();
        hasher.update(nonce_c);
        hasher.update(&x_bytes);
        hasher.update(&self.nonce);
        hasher.update(&y_bytes);
        hasher.update(&cert_pk_s);
        let sig_data = hasher.finalize();
        let sigma: Signature = self.signing_key.sign(&sig_data);
        let sigma_bytes = sigma.to_bytes().to_vec();

        println!("-> Signature created !");

        // Calculate mac_S
        // mac_S = HMAC(K2_S, SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || "ServerMAC"))
        let mut hasher = Sha256::new();
        hasher.update(nonce_c);
        hasher.update(&x_bytes);
        hasher.update(&self.nonce);
        hasher.update(&y_bytes);
        hasher.update(&sigma_bytes);
        hasher.update(&cert_pk_s);
        hasher.update(b"ServerMAC");
        let mac_s_data = hasher.finalize();
        let mac_s = compute_hmac(&k2_s, &mac_s_data);

        println!("-> MAC address of the server created !");

        Ok(ServerHello {
            nonce_s: self.nonce.clone(),
            y: self.dh_public.clone(),
            sigma: sigma_bytes,
            cert_pk_s,
            mac_s,
        })
    }

    /// Step 2: Receives ClientFinished and finalizes the handshake
    pub fn receive_client_finished(
        &mut self,
        client_finished: ClientFinished,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
    ) -> Result<(), String> {
        let nonce_c = &client_hello.nonce_c;
        let x = &client_hello.x;
        let nonce_s = &server_hello.nonce_s;
        let y = &server_hello.y;
        let sigma_bytes = &server_hello.sigma;
        let cert_pk_s = &server_hello.cert_pk_s;

        // Vérify mac_C
        let k2_c = self.k2_c.as_ref().ok_or("K2_C not derived")?;

        let x_bytes = x.to_sec1_bytes();
        let y_bytes = y.to_sec1_bytes();

        // mac_C = HMAC(K2_C, SHA256(nonce_C || X || nonce_S || Y || σ || cert_pk_S || "ClientMAC"))
        let mut hasher = Sha256::new();
        hasher.update(nonce_c);
        hasher.update(&x_bytes);
        hasher.update(nonce_s);
        hasher.update(&y_bytes);
        hasher.update(sigma_bytes);
        hasher.update(cert_pk_s);
        hasher.update(b"ClientMAC");
        let mac_c_data = hasher.finalize();

        if !verify_hmac(k2_c, &mac_c_data, &client_finished.mac_c) {
            return Err("Client MAC verification failed".to_string());
        }

        println!("-> MAC address of the client verified !");

        // Récupère le secret partagé stocké
        let shared_secret = self
            .shared_secret
            .as_ref()
            .ok_or("Shared secret not computed")?;

        // KeySchedule3
        let (k3_c, k3_s) = key_schedule_3(
            nonce_c,
            &x_bytes,
            nonce_s,
            &y_bytes,
            shared_secret,
            sigma_bytes,
            cert_pk_s,
            &server_hello.mac_s,
        );
        self.k3_c = Some(k3_c);
        self.k3_s = Some(k3_s);

        println!("-> KeySchedule3 calculated !");

        Ok(())
    }

    /// Retrieve the final K3 keys
    pub fn get_final_keys(&self) -> Option<(&[u8], &[u8])> {
        if let (Some(k3_c), Some(k3_s)) = (&self.k3_c, &self.k3_s) {
            Some((k3_c, k3_s))
        } else {
            None
        }
    }
}

/// TLS protocol demonstration
pub fn demonstrate_tls_handshake() {
    println!("\n=== Task 2: TLS Handshake Protocol ===\n");

    // 1. Initialisation
    println!("1. Client and server initialization ...");
    let mut client = TlsClient::new();
    let mut server = TlsServer::new();
    println!("-> Client and server initialized !\n");

    // 2. ClientHello
    println!("2. Client sends ClientHello ...");
    let client_hello = client.send_client_hello();
    println!(
        "-> Client sends ClientHello (nonce: {:02x?}...)\n",
        &client_hello.nonce_c[..4]
    );

    // 3. ServerHello
    println!("3. Server processes ClientHello and sends ServerHello ...");
    let server_hello = match server.receive_client_hello(client_hello.clone()) {
        Ok(sh) => {
            println!("-> ServerHello created !\n");
            sh
        }
        Err(e) => {
            println!("ERROR: {}\n", e);
            return;
        }
    };

    // 4. Client processes ServerHello and sends ClientFinished
    println!("4. Client processes ServerHello and sends ClientFinished ...");
    let client_finished = match client.receive_server_hello(server_hello.clone()) {
        Ok(cf) => {
            println!("-> ClientFinished created !\n");
            cf
        }
        Err(e) => {
            println!("ERROR: {}\n", e);
            return;
        }
    };

    // 5. Server processes ClientFinished
    println!("5. Server processes ClientFinished ...");
    match server.receive_client_finished(client_finished, &client_hello, &server_hello) {
        Ok(_) => println!("-> Handshake finished with success !\n"),
        Err(e) => {
            println!("ERROR: {}\n", e);
            return;
        }
    }

    // 6. Final key verification
    println!("6. Final key verification (K3)...");
    let client_keys = client.get_final_keys().expect("Client keys not derived");
    let server_keys = server.get_final_keys().expect("Server keys not derived");

    if client_keys.0 == server_keys.0 && client_keys.1 == server_keys.1 {
        println!("-> The K3 keys fit!");
        println!("   K3_C (First 16 bytes): {:02x?}", &client_keys.0[..16]);
        println!("   K3_S (First 16 bytes): {:02x?}", &client_keys.1[..16]);
    } else {
        println!("ERROR: Keys don't fit !");
    }

    println!("\n=== Handshake TLS finished with succes ! ===\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_tls_handshake() {
        let mut client = TlsClient::new();
        let mut server = TlsServer::new();

        // ClientHello
        let client_hello = client.send_client_hello();

        // ServerHello
        let server_hello = server
            .receive_client_hello(client_hello.clone())
            .expect("ServerHello failed");

        // ClientFinished
        let client_finished = client
            .receive_server_hello(server_hello.clone())
            .expect("ClientFinished failed");

        // Finalization
        server
            .receive_client_finished(client_finished, &client_hello, &server_hello)
            .expect("Finalization failed");

        // Verification
        let client_keys = client.get_final_keys().unwrap();
        let server_keys = server.get_final_keys().unwrap();

        assert_eq!(client_keys.0, server_keys.0);
        assert_eq!(client_keys.1, server_keys.1);
    }
}
