use oqs::sig::{Sig, Algorithm as SigAlgorithm};
use oqs::kem::{Kem, Algorithm as KemAlgorithm};
use std::fs::{File, create_dir_all};
use std::path::Path;
use chrono::Local;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::io::Write;

pub fn generate_key() {
    let mut rl = Editor::<()>::new().expect("Failed to create rustyline editor");

    loop {
        println!("Choose key type");
        println!("0. Exit");
        println!("1. Dilithium (Signature)");
        println!("2. Falcon (Signature)");
        println!("3. Mayo (Signature)");
        println!("4. MlDsa (Signature)");
        println!("5. Kyber (Encryption)");
        println!("6. hqc (Encryption)");
        println!("7. Bike (Encryption)");

        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                match line.trim() {
                    "1" => dilithium_key(&mut rl),
                    "2" => falcon_key(&mut rl),
                    "3" => mayo_key(&mut rl),
                   // "4" => mldsa_key(&mut rl),
                    "5" => kyber_key(&mut rl),
                    "6" => hqc_key(&mut rl),
                    "7" => bike_key(&mut rl),
                    "0" => {
                        println!("Exiting...");
                        break;
                    },
                    _ => println!("Invalid choice. Please try again."),
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}

fn dilithium_key(rl: &mut Editor<()>) {
    println!("Choose Dilithium variant:");
    println!("1. Dilithium2");
    println!("2. Dilithium3");
    println!("3. Dilithium5");

    let readline = rl.readline(">> ");
    let (algorithm, name) = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            match line.trim() {
                "1" => (SigAlgorithm::Dilithium2, "Dilithium2"),
                "2" => (SigAlgorithm::Dilithium3, "Dilithium3"),
                "3" => (SigAlgorithm::Dilithium5, "Dilithium5"),
                _ => {
                    println!("Invalid choice, using default (Dilithium2).");
                    (SigAlgorithm::Dilithium2, "Dilithium2") // Default to Dilithium2 if invalid input
                }
            }
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted. Using default (Dilithium2).");
            (SigAlgorithm::Dilithium2, "Dilithium2") // Default to Dilithium2 if interrupted
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    let sig = Sig::new(algorithm).expect("Failed to initialize Dilithium algorithm");

    let (public_key, secret_key) = sig.keypair().expect("Failed to generate keypair");

    let current_date = Local::now().format("%d%m%Y").to_string();

    println!("Enter the folder path where you want to save the keys:");

    let readline = rl.readline(">> ");
    let folder_path = match readline {
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

    if !Path::new(&folder_path).exists() {
        create_dir_all(&folder_path).expect("Failed to create folder");
    }

    let public_key_path = format!("{}/{}_public_key_{}.bin", folder_path, name, current_date);
    let secret_key_path = format!("{}/{}_secret_key_{}.bin", folder_path, name, current_date);

    let public_key_bytes = public_key.as_ref();
    let mut file = File::create(&public_key_path).expect("Failed to create public key file");
    file.write_all(public_key_bytes).expect("Failed to write public key");

    let secret_key_bytes = secret_key.as_ref();
    let mut file = File::create(&secret_key_path).expect("Failed to create secret key file");
    file.write_all(secret_key_bytes).expect("Failed to write secret key");

    println!("Keys have been saved to:");
    println!("Public Key: {}", public_key_path);
    println!("Secret Key: {}", secret_key_path);
}

fn falcon_key(rl: &mut Editor<()>) {
    println!("Choose Falcon variant:");
    println!("1. Falcon512");
    println!("2. Falcon1024");

    let readline = rl.readline(">> ");
    let (algorithm, name) = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            match line.trim() {
                "1" => (SigAlgorithm::Falcon512, "Falcon512"),
                "2" => (SigAlgorithm::Falcon1024, "Falcon1024"),
                _ => {
                    println!("Invalid choice, using default (Falcon1024).");
                    (SigAlgorithm::Falcon1024, "Falcon1024")
                }
            }
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted. Using default (Falcon1024).");
            (SigAlgorithm::Falcon1024, "Falcon1024")
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    let sig = Sig::new(algorithm).expect("Failed to initialize Dilithium algorithm");

    let (public_key, secret_key) = sig.keypair().expect("Failed to generate keypair");

    let current_date = Local::now().format("%d%m%Y").to_string();

    println!("Enter the folder path where you want to save the keys:");

    let readline = rl.readline(">> ");
    let folder_path = match readline {
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

    if !Path::new(&folder_path).exists() {
        create_dir_all(&folder_path).expect("Failed to create folder");
    }

    let public_key_path = format!("{}/{}_public_key_{}.bin", folder_path, name, current_date);
    let secret_key_path = format!("{}/{}_secret_key_{}.bin", folder_path, name, current_date);

    let public_key_bytes = public_key.as_ref();
    let mut file = File::create(&public_key_path).expect("Failed to create public key file");
    file.write_all(public_key_bytes).expect("Failed to write public key");

    let secret_key_bytes = secret_key.as_ref();
    let mut file = File::create(&secret_key_path).expect("Failed to create secret key file");
    file.write_all(secret_key_bytes).expect("Failed to write secret key");

    println!("Keys have been saved to:");
    println!("Public Key: {}", public_key_path);
    println!("Secret Key: {}", secret_key_path);
}

fn mayo_key(rl: &mut Editor<()>) {
    println!("Choose Mayo variant:");
    println!("1. Mayo1");
    println!("2. Mayo2");
    println!("3. Mayo3");
    println!("4. Mayo5");

    let readline = rl.readline(">> ");
    let (algorithm, name) = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            match line.trim() {
                "1" => (SigAlgorithm::Mayo1, "Mayo1"),
                "2" => (SigAlgorithm::Mayo2, "Mayo2"),
                "3" => (SigAlgorithm::Mayo3, "Mayo3"),
                "4" => (SigAlgorithm::Mayo5, "Mayo5"),
                _ => {
                    println!("Invalid choice, using default (Mayo5).");
                    (SigAlgorithm::Mayo5, "Mayo5")
                }
            }
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted. Using default (Mayo5).");
            (SigAlgorithm::Mayo5, "Mayo5")
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    // Initialize the Dilithium algorithm
    let sig = Sig::new(algorithm).expect("Failed to initialize Dilithium algorithm");

    // Generate the keypair
    let (public_key, secret_key) = sig.keypair().expect("Failed to generate keypair");

    // Get current date in DDMMYYYY format
    let current_date = Local::now().format("%d%m%Y").to_string();

    // Ask the user for the folder where they want to save the keys
    println!("Enter the folder path where you want to save the keys:");

    let readline = rl.readline(">> ");
    let folder_path = match readline {
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

    if !Path::new(&folder_path).exists() {
        // If the folder doesn't exist, create it
        create_dir_all(&folder_path).expect("Failed to create folder");
    }

    // Construct the file paths for saving the binary keys with date and meaningful names
    let public_key_path = format!("{}/{}_public_key_{}.bin", folder_path, name, current_date);
    let secret_key_path = format!("{}/{}_secret_key_{}.bin", folder_path, name, current_date);

    // Convert public_key to bytes and save it as a raw binary file
    let public_key_bytes = public_key.as_ref();
    let mut file = File::create(&public_key_path).expect("Failed to create public key file");
    file.write_all(public_key_bytes).expect("Failed to write public key");

    // Convert secret_key to bytes and save it as a raw binary file
    let secret_key_bytes = secret_key.as_ref();
    let mut file = File::create(&secret_key_path).expect("Failed to create secret key file");
    file.write_all(secret_key_bytes).expect("Failed to write secret key");

    println!("Keys have been saved to:");
    println!("Public Key: {}", public_key_path);
    println!("Secret Key: {}", secret_key_path);
}





fn kyber_key(rl: &mut Editor<()>) {
    println!("Choose Kyber variant:");
    println!("1. Kyber512");
    println!("2. Kyber768");
    println!("3. Kyber1024");

    let readline = rl.readline(">> ");
    let (algorithm, name) = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            match line.trim() {
                "1" => (KemAlgorithm::Kyber512, "Kyber512"),
                "2" => (KemAlgorithm::Kyber768, "Kyber768"),
                "3" => (KemAlgorithm::Kyber1024, "Kyber1024"),
                _ => {
                    println!("Invalid choice, using default (Kyber512).");
                    (KemAlgorithm::Kyber512, "Kyber512") // Default to Kyber512 if invalid input
                }
            }
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted. Using default (Kyber512).");
            (KemAlgorithm::Kyber512, "Kyber512") // Default to Kyber512 if interrupted
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    // Initialize the Kyber algorithm
    let kem = Kem::new(algorithm).expect("Failed to initialize Kyber algorithm");

    // Generate the keypair
    let (public_key, secret_key) = kem.keypair().expect("Failed to generate keypair");

    // Get current date in DDMMYYYY format
    let current_date = Local::now().format("%d%m%Y").to_string();

    // Ask the user for the folder where they want to save the keys
    println!("Enter the folder path where you want to save the keys:");

    let readline = rl.readline(">> ");
    let folder_path = match readline {
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

    if !Path::new(&folder_path).exists() {
        // If the folder doesn't exist, create it
        create_dir_all(&folder_path).expect("Failed to create folder");
    }

    // Construct the file paths for saving the binary keys with date and meaningful names
    let public_key_path = format!("{}/{}_public_key_{}.bin", folder_path, name, current_date);
    let secret_key_path = format!("{}/{}_secret_key_{}.bin", folder_path, name, current_date);

    // Convert public_key to bytes and save it as a raw binary file
    let public_key_bytes = public_key.as_ref();
    let mut file = File::create(&public_key_path).expect("Failed to create public key file");
    file.write_all(public_key_bytes).expect("Failed to write public key");

    // Convert secret_key to bytes and save it as a raw binary file
    let secret_key_bytes = secret_key.as_ref();
    let mut file = File::create(&secret_key_path).expect("Failed to create secret key file");
    file.write_all(secret_key_bytes).expect("Failed to write secret key");

    println!("Keys have been saved to:");
    println!("Public Key: {}", public_key_path);
    println!("Secret Key: {}", secret_key_path);
}

fn hqc_key(rl: &mut Editor<()>) {
    println!("Choose HQC variant:");
    println!("1. HQC-128");
    println!("2. HQC-192");
    println!("3. HQC-256");

    let readline = rl.readline(">> ");
    let (algorithm, name) = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            match line.trim() {
                "1" => (KemAlgorithm::Hqc128, "Hqc128"),
                "2" => (KemAlgorithm::Hqc192, "Hqc192"),
                "3" => (KemAlgorithm::Hqc256, "Hqc256"),
                _ => {
                    println!("Invalid choice, using default (HQC256).");
                    (KemAlgorithm::Hqc256, "Hqc256")
                }
            }
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted. Using default (HQC-128).");
            (KemAlgorithm::Hqc256, "Hqc256")
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    // Initialize the HQC algorithm
    let kem = Kem::new(algorithm).expect("Failed to initialize HQC algorithm");

    // Generate the keypair
    let (public_key, secret_key) = kem.keypair().expect("Failed to generate keypair");

    // Get current date in DDMMYYYY format
    let current_date = Local::now().format("%d%m%Y").to_string();

    // Ask the user for the folder where they want to save the keys
    println!("Enter the folder path where you want to save the keys:");

    let readline = rl.readline(">> ");
    let folder_path = match readline {
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

    if !Path::new(&folder_path).exists() {
        // If the folder doesn't exist, create it
        create_dir_all(&folder_path).expect("Failed to create folder");
    }

    // Construct the file paths for saving the binary keys with date and meaningful names
    let public_key_path = format!("{}/{}_public_key_{}.bin", folder_path, name, current_date);
    let secret_key_path = format!("{}/{}_secret_key_{}.bin", folder_path, name, current_date);

    // Convert public_key to bytes and save it as a raw binary file
    let public_key_bytes = public_key.as_ref();
    let mut file = File::create(&public_key_path).expect("Failed to create public key file");
    file.write_all(public_key_bytes).expect("Failed to write public key");

    // Convert secret_key to bytes and save it as a raw binary file
    let secret_key_bytes = secret_key.as_ref();
    let mut file = File::create(&secret_key_path).expect("Failed to create secret key file");
    file.write_all(secret_key_bytes).expect("Failed to write secret key");

    println!("Keys have been saved to:");
    println!("Public Key: {}", public_key_path);
    println!("Secret Key: {}", secret_key_path);
}

fn bike_key(rl: &mut Editor<()>) {
    println!("Choose Bike variant:");
    println!("1. BikeL1");
    println!("2. BikeL3");
    println!("3. BikeL5");

    let readline = rl.readline(">> ");
    let (algorithm, name) = match readline {
        Ok(line) => {
            rl.add_history_entry(line.as_str());
            match line.trim() {
                "1" => (KemAlgorithm::BikeL1, "BikeL1"),
                "2" => (KemAlgorithm::BikeL3, "BikeL3"),
                "3" => (KemAlgorithm::BikeL5, "BikeL5"),
                _ => {
                    println!("Invalid choice, using default (BikeL5).");
                    (KemAlgorithm::BikeL5, "BikeL5")
                }
            }
        },
        Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
            println!("Operation interrupted. Using default (HQC-128).");
            (KemAlgorithm::BikeL5, "BikeL5")
        },
        Err(err) => {
            println!("Error: {:?}", err);
            return;
        }
    };

    // Initialize the HQC algorithm
    let kem = Kem::new(algorithm).expect("Failed to initialize HQC algorithm");

    // Generate the keypair
    let (public_key, secret_key) = kem.keypair().expect("Failed to generate keypair");

    // Get current date in DDMMYYYY format
    let current_date = Local::now().format("%d%m%Y").to_string();

    // Ask the user for the folder where they want to save the keys
    println!("Enter the folder path where you want to save the keys:");

    let readline = rl.readline(">> ");
    let folder_path = match readline {
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

    if !Path::new(&folder_path).exists() {
        // If the folder doesn't exist, create it
        create_dir_all(&folder_path).expect("Failed to create folder");
    }

    // Construct the file paths for saving the binary keys with date and meaningful names
    let public_key_path = format!("{}/{}_public_key_{}.bin", folder_path, name, current_date);
    let secret_key_path = format!("{}/{}_secret_key_{}.bin", folder_path, name, current_date);

    // Convert public_key to bytes and save it as a raw binary file
    let public_key_bytes = public_key.as_ref();
    let mut file = File::create(&public_key_path).expect("Failed to create public key file");
    file.write_all(public_key_bytes).expect("Failed to write public key");

    // Convert secret_key to bytes and save it as a raw binary file
    let secret_key_bytes = secret_key.as_ref();
    let mut file = File::create(&secret_key_path).expect("Failed to create secret key file");
    file.write_all(secret_key_bytes).expect("Failed to write secret key");

    println!("Keys have been saved to:");
    println!("Public Key: {}", public_key_path);
    println!("Secret Key: {}", secret_key_path);
}
