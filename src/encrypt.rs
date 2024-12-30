use oqs::kem::{Kem, Algorithm as KemAlgorithm, SecretKey};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use rustyline::error::ReadlineError;
use rustyline::Editor;

pub fn encrypt_file(rl: &mut Editor<()>) {
    // Prompt for the private key file path
    println!("Enter the path to your private key file:");

    let readline = rl.readline(">> ");
    let private_key_path = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            line.trim_matches(&['"', '\''][..]).trim().to_string()
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted.");
            return;
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    // Read the private key
    let mut private_key_file = match File::open(&private_key_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open private key file: {:?}", err);
            return;
        }
    };
    let mut private_key_bytes = vec![];
    private_key_file.read_to_end(&mut private_key_bytes).expect("Failed to read private key file");

    // Determine the algorithm from the file name
    let algorithm = if private_key_path.contains("Kyber512") {
        KemAlgorithm::Kyber512
    } else if private_key_path.contains("Kyber768") {
        KemAlgorithm::Kyber768
    } else if private_key_path.contains("Kyber1024") {
        KemAlgorithm::Kyber1024
    } else if private_key_path.contains("BIKE1L1") {
        KemAlgorithm::BikeL1
    } else if private_key_path.contains("BIKE1L3") {
        KemAlgorithm::BikeL3
    } else if private_key_path.contains("BIKE1L5") {
        KemAlgorithm::BikeL5
    } else if private_key_path.contains("HQC128") {
        KemAlgorithm::Hqc128
    } else if private_key_path.contains("HQC192") {
        KemAlgorithm::Hqc192
    } else if private_key_path.contains("HQC256") {
        KemAlgorithm::Hqc256
    } else {
        println!("Unknown algorithm in private key file name.");
        return;
    };

    // Initialize the encryption algorithm
    let kem = Kem::new(algorithm).expect("Failed to initialize encryption algorithm");

    // Load the private key
    let secret_key = SecretKey::from_bytes(&private_key_bytes).expect("Failed to load private key");

    // Prompt for the file to encrypt
    println!("Enter the path to the file you want to encrypt:");

    let readline = rl.readline(">> ");
    let file_to_encrypt_path = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            line.trim_matches(&['"', '\''][..]).trim().to_string()
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted.");
            return;
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    // Read the file to encrypt
    let mut file_to_encrypt = match File::open(&file_to_encrypt_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open file to encrypt: {:?}", err);
            return;
        }
    };
    let mut file_bytes = vec![];
    file_to_encrypt.read_to_end(&mut file_bytes).expect("Failed to read file to encrypt");

    // Encrypt the file
    let (ciphertext, encapsulated_key) = kem.encapsulate(&secret_key).expect("Failed to encrypt the file");

    // Save the encrypted file
    let encrypted_file_path = format!("{}.enc", file_to_encrypt_path);
    let mut encrypted_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&encrypted_file_path)
        .expect("Failed to create encrypted file");
    encrypted_file.write_all(ciphertext.as_slice()).expect("Failed to write encrypted file");

    println!("File encrypted successfully. Encrypted file saved to: {}", encrypted_file_path);
}

fn main() {
    // Create a new rustyline Editor
    let mut rl = Editor::<()>::new();

    // Encrypt a file
    encrypt_file(&mut rl);
}
