use std::fs::{self, File};
use sha1::{Sha1, Digest};
use aes::{Aes128, cipher::StreamCipher};
use ctr::Ctr128BE;
use aes::cipher::KeyIvInit;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::io::{self, Result, Read};
use file_format::{FileFormat, Kind};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    password: Option<String>,
    #[arg(short, long)]
    encrypted_images_path: Option<String>,

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
        max_pin: Option<i32>,
        #[arg(short, long)]
        wordlist: Option<String>,
    },
}

fn create_extension_map() -> HashMap<&'static str, &'static str> {
    let mut extension_map = HashMap::new();

    extension_map.insert("mp4", "vp3");
    extension_map.insert("webm", "vo1");
    extension_map.insert("mpg", "v27");
    extension_map.insert("avi", "vb9");
    extension_map.insert("mov", "v77");
    extension_map.insert("wmv", "v78");
    extension_map.insert("dv", "v82");
    extension_map.insert("divx", "vz9");
    extension_map.insert("ogv", "vi3");
    extension_map.insert("h261", "v1u");
    extension_map.insert("h264", "v6m");
    //extension_map.insert("jpeg", "6zu");
    extension_map.insert("jpg", "6zu");
    extension_map.insert("gif", "tr7");
    extension_map.insert("png", "p50");
    extension_map.insert("bmp", "8ur");
    extension_map.insert("tif", "33t");
    extension_map.insert("tiff", "33t");
    extension_map.insert("webp", "20i");
    extension_map.insert("heic", "v93");
    extension_map.insert("eps", "v91");
    extension_map.insert("3gpp", "v80");
    extension_map.insert("ts", "vo4");
    extension_map.insert("mkv", "v99");
    extension_map.insert("mpeg", "vr2");
    extension_map.insert("dpg", "vv3");
    extension_map.insert("flv", "v91");
    extension_map.insert("rmvb", "v81");
    extension_map.insert("vob", "vz8");
    extension_map.insert("asf", "wi2");
    extension_map.insert("h263", "vi4");
    extension_map.insert("f4v", "v2u");
    extension_map.insert("m4v", "v76");
    extension_map.insert("ram", "v75");
    extension_map.insert("rm", "v74");
    extension_map.insert("mts", "v3u");
    extension_map.insert("dng", "v92");
    extension_map.insert("ps", "r89");
    extension_map.insert("3gp", "v79");

    extension_map
}

fn read_header(file_path: &str) -> io::Result<Vec<u8>> {
    // Open the file.
    let mut file = File::open(file_path)?;

    // Create a buffer to hold the first 32 bytes.
    let mut buffer = vec![0; 32]; // Initialize a vector with 32 zeros.

    // Read up to 32 bytes from the beginning of the file.
    let bytes_read = file.read(&mut buffer)?;

    // Resize the buffer in case less than 32 bytes were read.
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

fn match_ext<P: AsRef<Path>>(
    dir: P,
    extension_map: &HashMap<&str, &str>,
) -> Result<Option<PathBuf>> {
    let dir = dir.as_ref();
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let is_matching_extension = extension_map.iter().any(|(_, &value)| value == ext);
                    if is_matching_extension {
                        return Ok(Some(path));
                    }
                }
            }
        }
    }
    Ok(None)
}

fn find_key_for_value<'a, K, V>(map: &'a HashMap<K, V>, value: &V) -> Option<&'a K>
where
    K: Eq + std::hash::Hash,
    V: PartialEq,
{
    map.iter()
        .find_map(|(key, val)| if val == value { Some(key) } else { None })
}



// genuinly the worst code i have ever written
// there was a time where only me and god know what was going on here 
//
// now it is only god

fn bruteforce_password(command: Commands) -> Result<()> {

    match command {
        Commands::Bruteforce {
            encrypted_images_path,
            max_pin,
            wordlist,
        } => {
            println!("Handling Bruteforce...");
            println!("Attempting bruteforce on {:?} directory", encrypted_images_path);
            if max_pin.is_some() { println!("Max PIN number set to: {:?}", max_pin.unwrap()); }
            if wordlist.is_some() { println!("Wordlist Path: {:?}", wordlist.unwrap()); }

            let extension_map = create_extension_map();
            match match_ext(encrypted_images_path.clone(), &extension_map)? {
                Some(path) => {
                    println!("found matching extension: {:?}", path);
                    // find the target file type
                    let target_type = path.extension().unwrap().to_str().unwrap();
                    match find_key_for_value(&extension_map, &target_type) {
                        Some(key) => {
                            println!("found key for value: {}: {}", target_type, key);
                            for num in 1..=max_pin.unwrap() {
                                let passcode = format!("{:0width$}", num, width = max_pin.unwrap().to_string().len());
                                 match fs::read_dir(encrypted_images_path.clone()) {
                                    Ok(entries) => {
                                        for entry in entries {
                                            match entry {
                                                Ok(entry) => {
                                                    let path = entry.path();
                                                    if path.is_file() {
                                                        let decrypted_attempt = bruteforce_decrypt(&passcode, &path.as_path().display().to_string());
                                                        let fmt = FileFormat::from_bytes(decrypted_attempt.as_slice());
                                                        if *fmt.extension() == **key {
                                                            println!("found the passcode: {:?}", passcode);
                                                        } 
                                                    }
                                                },
                                                Err(e) => println!("Error reading directory entry: {}", e),
                                            }
                                        }
                                    },
                                    Err(e) => println!("Error reading directory: {}", e),
                                }
                            }
                        },
                        None => println!("No key found {}", target_type),
                    }
                    // generate passcodes and pass to the decrypt function
                    // check return for vaild file type

                     
                },
                None => println!("Failed to find valid file extension"),
            }
        },
        
    }

    Ok(())
}

fn decrypt_aes_ctr(key: &[u8], iv: &[u8], enc_img: &[u8]) -> Vec<u8> {
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(key, iv).unwrap();
    let mut data = enc_img.to_vec();
    cipher.apply_keystream(&mut data);
    data
}

fn read_enc_image(path: &str) -> Vec<u8> {
    fs::read(path).expect("Cannot read file")
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
