use crypto_homework::{
    task1_signed_dh, task2_tls_handshake, task3_ecdsa_attack, task4_pq_tls, task5_kem_tls,
    task6_comparison,
};

fn main() {
    println!("Crypto Homework - TLS Implementation");
    println!("=====================================\n");

    // Task 1: Signed Diffie-Hellman
    task1_signed_dh::demonstrate_signed_dh();

    // Task 2: TLS Handshake
    task2_tls_handshake::demonstrate_tls_handshake();

    // Task 3: ECDSA Attack
    task3_ecdsa_attack::demonstrate_ecdsa_attack();

    // Task 4: PQ-TLS Handshake
    task4_pq_tls::demonstrate_pq_tls();

    // Task 5: KEM-TLS Handshake
    task5_kem_tls::demonstrate_kem_tls();

    // Task 6: Performance Comparison
    task6_comparison::compare_protocols();
}
