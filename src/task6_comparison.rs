use crate::task4_pq_tls::{PqTlsClient, PqTlsServer};
use crate::task5_kem_tls::{KemTlsClient, KemTlsServer};
use std::time::{Duration, Instant};

/// Performance metrics for a protocol
#[derive(Debug, Clone)]
pub struct ProtocolMetrics {
    pub name: String,
    pub handshake_times: Vec<Duration>,
    pub avg_handshake_time: Duration,
    pub min_handshake_time: Duration,
    pub max_handshake_time: Duration,
    pub key_sizes: KeySizes,
}

#[derive(Debug, Clone)]
pub struct KeySizes {
    pub public_key_size: usize,
    pub ciphertext_size: usize,
    pub signature_size: Option<usize>, // None for KEM-TLS
    pub total_handshake_size: usize,
}

/// Run PQ-TLS handshake and measure performance
fn benchmark_pq_tls(iterations: usize) -> ProtocolMetrics {
    let mut handshake_times = Vec::new();

    println!("Benchmarking PQ-TLS ({} iterations)...", iterations);

    for i in 0..iterations {
        let start = Instant::now();

        let mut client = PqTlsClient::new();
        let mut server = PqTlsServer::new();

        let client_hello = client.send_client_hello();
        let server_hello = server.receive_client_hello(client_hello.clone()).unwrap();
        let client_finished = client.receive_server_hello(server_hello.clone()).unwrap();
        server
            .receive_client_finished(client_finished, &client_hello, &server_hello)
            .unwrap();

        let elapsed = start.elapsed();
        handshake_times.push(elapsed);

        if (i + 1) % 10 == 0 {
            print!(".");
            use std::io::{self, Write};
            io::stdout().flush().unwrap();
        }
    }
    println!(" Done!");

    // Calculate statistics
    let total: Duration = handshake_times.iter().sum();
    let avg = total / iterations as u32;
    let min = *handshake_times.iter().min().unwrap();
    let max = *handshake_times.iter().max().unwrap();

    // Key sizes for PQ-TLS (Kyber768 + Dilithium3)
    let kyber_pk_size = 1184; // Kyber768 public key
    let kyber_ct_size = 1088; // Kyber768 ciphertext
    let dilithium_pk_size = 1952; // Dilithium3 public key
    let dilithium_sig_size = 3293; // Dilithium3 signature

    let key_sizes = KeySizes {
        public_key_size: kyber_pk_size + dilithium_pk_size,
        ciphertext_size: kyber_ct_size,
        signature_size: Some(dilithium_sig_size),
        total_handshake_size: kyber_pk_size
            + kyber_ct_size
            + dilithium_pk_size
            + dilithium_sig_size
            + 64, // +64 for nonces
    };

    ProtocolMetrics {
        name: "PQ-TLS (Kyber768 + Dilithium3)".to_string(),
        handshake_times,
        avg_handshake_time: avg,
        min_handshake_time: min,
        max_handshake_time: max,
        key_sizes,
    }
}

/// Run KEM-TLS handshake and measure performance
fn benchmark_kem_tls(iterations: usize) -> ProtocolMetrics {
    let mut handshake_times = Vec::new();

    println!("Benchmarking KEM-TLS ({} iterations)...", iterations);

    for i in 0..iterations {
        let start = Instant::now();

        let mut client = KemTlsClient::new();
        let mut server = KemTlsServer::new();

        let client_hello = client.send_client_hello();
        let server_hello = server.receive_client_hello(client_hello.clone()).unwrap();
        let client_finished = client.receive_server_hello(server_hello.clone()).unwrap();
        server
            .receive_client_finished(client_finished, &client_hello, &server_hello)
            .unwrap();

        let elapsed = start.elapsed();
        handshake_times.push(elapsed);

        if (i + 1) % 10 == 0 {
            print!(".");
            use std::io::{self, Write};
            io::stdout().flush().unwrap();
        }
    }
    println!(" Done!");

    // Calculate statistics
    let total: Duration = handshake_times.iter().sum();
    let avg = total / iterations as u32;
    let min = *handshake_times.iter().min().unwrap();
    let max = *handshake_times.iter().max().unwrap();

    // Key sizes for KEM-TLS (2x Kyber768)
    let kyber_pk_size = 1184; // Kyber768 public key
    let kyber_ct_size = 1088; // Kyber768 ciphertext

    let key_sizes = KeySizes {
        public_key_size: kyber_pk_size * 2, // Two Kyber public keys
        ciphertext_size: kyber_ct_size * 2, // Two ciphertexts
        signature_size: None,
        total_handshake_size: (kyber_pk_size + kyber_ct_size) * 2 + 64, // +64 for nonces
    };

    ProtocolMetrics {
        name: "KEM-TLS (Kyber768 only)".to_string(),
        handshake_times,
        avg_handshake_time: avg,
        min_handshake_time: min,
        max_handshake_time: max,
        key_sizes,
    }
}

/// Display comparison results
fn display_comparison(pq_metrics: &ProtocolMetrics, kem_metrics: &ProtocolMetrics) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║         Performance Comparison: PQ-TLS vs KEM-TLS             ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // Time comparison
    println!("⏱️  HANDSHAKE TIME COMPARISON");
    println!("─────────────────────────────────────────────────────────────────");
    println!("Protocol                          Avg        Min        Max");
    println!("─────────────────────────────────────────────────────────────────");
    println!(
        "{:<30} {:>8.2?}   {:>8.2?}   {:>8.2?}",
        pq_metrics.name,
        pq_metrics.avg_handshake_time,
        pq_metrics.min_handshake_time,
        pq_metrics.max_handshake_time
    );
    println!(
        "{:<30} {:>8.2?}   {:>8.2?}   {:>8.2?}",
        kem_metrics.name,
        kem_metrics.avg_handshake_time,
        kem_metrics.min_handshake_time,
        kem_metrics.max_handshake_time
    );
    println!("─────────────────────────────────────────────────────────────────");

    // Speed comparison
    let speedup =
        pq_metrics.avg_handshake_time.as_secs_f64() / kem_metrics.avg_handshake_time.as_secs_f64();

    if speedup > 1.0 {
        println!("✓ KEM-TLS is {:.2}x FASTER than PQ-TLS", speedup);
    } else {
        println!("✓ PQ-TLS is {:.2}x FASTER than KEM-TLS", 1.0 / speedup);
    }

    // Size comparison
    println!("\n📦 DATA SIZE COMPARISON (bytes)");
    println!("─────────────────────────────────────────────────────────────────");
    println!("Component                    PQ-TLS        KEM-TLS      Difference");
    println!("─────────────────────────────────────────────────────────────────");

    println!(
        "{:<25} {:>10}    {:>10}    {:>+10}",
        "Public Keys",
        pq_metrics.key_sizes.public_key_size,
        kem_metrics.key_sizes.public_key_size,
        (kem_metrics.key_sizes.public_key_size as i32
            - pq_metrics.key_sizes.public_key_size as i32)
    );

    println!(
        "{:<25} {:>10}    {:>10}    {:>+10}",
        "Ciphertexts",
        pq_metrics.key_sizes.ciphertext_size,
        kem_metrics.key_sizes.ciphertext_size,
        (kem_metrics.key_sizes.ciphertext_size as i32
            - pq_metrics.key_sizes.ciphertext_size as i32)
    );

    if let Some(sig_size) = pq_metrics.key_sizes.signature_size {
        println!(
            "{:<25} {:>10}    {:>10}    {:>+10}",
            "Signatures",
            sig_size,
            0,
            -(sig_size as i32)
        );
    }

    println!("─────────────────────────────────────────────────────────────────");
    println!(
        "{:<25} {:>10}    {:>10}    {:>+10}",
        "TOTAL HANDSHAKE SIZE",
        pq_metrics.key_sizes.total_handshake_size,
        kem_metrics.key_sizes.total_handshake_size,
        (kem_metrics.key_sizes.total_handshake_size as i32
            - pq_metrics.key_sizes.total_handshake_size as i32)
    );
    println!("─────────────────────────────────────────────────────────────────");

    let size_ratio = pq_metrics.key_sizes.total_handshake_size as f64
        / kem_metrics.key_sizes.total_handshake_size as f64;

    if size_ratio > 1.0 {
        println!(
            "✓ KEM-TLS uses {:.1}% LESS bandwidth than PQ-TLS",
            (1.0 - 1.0 / size_ratio) * 100.0
        );
    } else {
        println!(
            "✓ PQ-TLS uses {:.1}% LESS bandwidth than KEM-TLS",
            (1.0 - size_ratio) * 100.0
        );
    }

    // Trade-offs analysis
    println!("\n🔍 TRADE-OFFS ANALYSIS");
    println!("─────────────────────────────────────────────────────────────────");
    println!("PQ-TLS (Kyber + Dilithium):");
    println!("  ✓ Provides authentication via digital signatures");
    println!("  ✓ Non-repudiation (signatures can prove identity)");
    println!("  ✗ Larger handshake size (includes signature)");
    println!("  ✗ Slower due to signature operations");
    println!();
    println!("KEM-TLS (Kyber only):");
    println!("  ✓ Faster handshake (no signature operations)");
    println!("  ✓ Smaller handshake size (no signatures)");
    println!("  ✗ No authentication (vulnerable to MITM without certificates)");
    println!("  ✗ No non-repudiation");
    println!("─────────────────────────────────────────────────────────────────");

    println!("\n💡 RECOMMENDATION");
    println!("─────────────────────────────────────────────────────────────────");
    println!("• Use PQ-TLS when authentication is critical (e.g., HTTPS, VPN)");
    println!("• Use KEM-TLS when speed matters and authentication can be");
    println!("  provided by other means (e.g., pre-shared keys, certificates)");
    println!("─────────────────────────────────────────────────────────────────\n");
}

/// Main comparison function
pub fn compare_protocols() {
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("      Task 6: Performance Comparison (PQ-TLS vs KEM-TLS)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let iterations = 100;

    // Benchmark PQ-TLS
    let pq_metrics = benchmark_pq_tls(iterations);

    println!();

    // Benchmark KEM-TLS
    let kem_metrics = benchmark_kem_tls(iterations);

    // Display comparison
    display_comparison(&pq_metrics, &kem_metrics);
}
