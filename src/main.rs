use std::fs::{self, File};
use sha1::{Sha1, Digest};
use aes::{Aes128, cipher::{StreamCipher, generic_array::GenericArray}};
use ctr::Ctr128BE;
use aes::cipher::KeyIvInit;
use clap::{builder::OsStr, Parser, Subcommand};
use std::io::{self, Result, Read, prelude::*, BufReader};
use file_format::FileFormat;
use base64::{alphabet, engine::{self, general_purpose}, Engine};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut};
use std::path::Path; 

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    password: Option<String>,
    #[arg(short, long)]
    encrypted_images_path: Option<String>,
    #[arg(short, long)]
    output: String,
    #[arg(short, long)]
    file_name: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Attempt Bruteforce
    Bruteforce {
        #[arg(short, long)]
        encrypted_images_path: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        max_pin: Option<i32>,
        #[arg(short, long)]
        wordlist: Option<String>,
    },

    DecryptFilename {
        #[arg(short, long)]
        file_name: String,
    },
}

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

fn read_header(file_path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0; 32]; 
    let bytes_read = file.read(&mut buffer)?;
    buffer.resize(bytes_read, 0);
    Ok(buffer)
}

fn bruteforce_decrypt(password: &str, path: &str)  -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let key = result[0..16].to_vec();
    let header = read_header(path);
    let decrypt_attempt = decrypt_aes_ctr(&key, &key, &header.unwrap());
    decrypt_attempt

}

fn decrypt_with_password(password: &str, path: &str)  {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let key = result[0..16].to_vec();
    let enc_img = read_enc_image(path);
    let decrypted = decrypt_aes_ctr(&key, &key, &enc_img);
    println!("{:?}", decrypted);

}

fn decrypt_aes_ctr(key: &[u8], iv: &[u8], enc_img: &[u8]) -> Vec<u8> {
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(key, iv).unwrap();
    let mut data = enc_img.to_vec();
    cipher.apply_keystream(&mut data);
    data
}

fn ensure_b64_padding(filename: &str) -> String {
    let remainder = filename.len() % 4;
    if remainder == 0 { 
        filename.to_string()
    } else { 
        let padding_needed = 4 - remainder; 
        format!("{}{}", filename, "=".repeat(padding_needed))
    }
}

fn decrypt_filename(filename: &str) {
    let key_bytes = b"202cb962ac59123\x00"; // Key must be 16 bytes for AES128
    let key = GenericArray::from_slice(key_bytes); // Convert to GenericArray

    let encoded_fname = "7z2rdffDKyELLqEp9fiVDQ=="; // Ensure your encoded string is correctly padded
    let encoded_fname = Path::new(filename).file_stem().unwrap().to_str().unwrap();
    let formatted_filename = ensure_b64_padding(encoded_fname);
    println!("{:?}", formatted_filename);

    let decoded_fname_result = base64::decode(formatted_filename); // Base64 decoding
    println!("{:?}", decoded_fname_result);
    
    match decoded_fname_result {
        Ok(mut decoded_fname) => {
            let cipher = Aes128CbcDec::new(key, key);
            match cipher.decrypt_padded_mut::<Pkcs7>(&mut decoded_fname) {
                Ok(decrypted) => println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted)),
                Err(e) => println!("Decryption failed: {:?}", e),
            }
        },
        Err(e) => println!("Base64 decoding failed: {:?}", e),
    }
}

fn read_enc_image(path: &str) -> Vec<u8> {
    fs::read(path).expect("Cannot read file")
}


fn bruteforce_password(command: Commands) -> io::Result<()> {
    match command {Commands::Bruteforce {encrypted_images_path, max_pin, wordlist, output} => {
        let entries = fs::read_dir(encrypted_images_path)?;
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() {
                if let Some(ref wordlist_path) = wordlist {
                    println!("Beginning bruteforce with Wordlist");
                    let wordlist_file = File::open(wordlist_path)?;
                    let reader = BufReader::new(wordlist_file);
                    for line_result in reader.lines() {
                        if let Ok(password) = line_result {
                            let decrypt_attempt = bruteforce_decrypt(&password, path.to_str().unwrap());
                            let fmt = FileFormat::from_bytes(&decrypt_attempt);
                            if *fmt.extension() != *"bin" {
                                println!("Found passcode: {:?} with extension: {:?}", password, fmt.extension());
                                break; 
                            }
                        }
                    }
                }

                if let Some(max) = max_pin {
                    println!("Beginning bruteforce");
                    for num in 1..=max {
                        let pin_attempt = format!("{:0>width$}", num, width = max.to_string().len());
                        let decrypt_attempt = bruteforce_decrypt(&pin_attempt, path.to_str().unwrap());
                        let fmt = FileFormat::from_bytes(&decrypt_attempt);
                        if *fmt.extension() != *"bin" {
                            println!("Found passcode: {:?} with extension: {:?}", pin_attempt, fmt.extension());
                            break; 
                        }
                    }
                }
            }
        }
    },
    Commands::DecryptFilename { file_name } => {
        println!("filename: {:?}", file_name);
        println!("This doesnt work no idea why");
        //let _ = decrypt_filename(&file_name);
    },
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Some(command) = cli.command {
        let _ = bruteforce_password(command);
    }
    if cli.password.as_deref().is_some() && cli.encrypted_images_path.as_deref().is_some() {
        println!("password: {:?} path: {:?}", cli.password, cli.encrypted_images_path);
        decrypt_with_password(&cli.password.unwrap(), &cli.encrypted_images_path.unwrap());
    }
}

