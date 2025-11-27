use crypto_homework::{task1_signed_dh, task2_tls_handshake, task3_ecdsa_attack};

fn main() {
    println!("Crypto Homework - TLS Implementation");
    println!("=====================================\n");

    // Task 1: Signed Diffie-Hellman
    task1_signed_dh::demonstrate_signed_dh();

    // Task 2: TLS Handshake
    task2_tls_handshake::demonstrate_tls_handshake();

    // Task 3: ECDSA Attack
    task3_ecdsa_attack::demonstrate_ecdsa_attack();
}
