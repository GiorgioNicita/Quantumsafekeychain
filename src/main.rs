use rustyline::Editor;
use rustyline::error::ReadlineError;

mod encrypt;
mod decrypt;
mod keygen;
mod sign;
mod verify;

fn main() {
    println!("Welcome to openquantumkeychain");

    let mut rl = Editor::<()>::new().expect("Failed to create rustyline editor");

    loop {
        println!("Choose an option:");
        println!("1. Generate a Key");
        println!("2. Encrypt a File");
        println!("3. Decrypt a File");
        println!("4. Sign a file");
        println!("5. Verify a signature");
        println!("6. Exit");

        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                match line.trim() {
                    "1" => keygen::generate_key(),
                    //"2" => encrypt::encrypt_file(),
                    //"3" => decrypt::decrypt_file(),
                    //"4" => sign::sign_file(),
                    //"5" => verify::verify_file(),
                    "6" => {
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
