use crate::config::{Config};
use crate::utils::{exit_error, get_file_size_string, get_blocked_file_name_chars};

use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::metadata;
use std::{panic, process, thread, time};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharedFile {
    pub path: String,
    pub is_directory: bool,
    pub files: Vec<SharedFile>,
    pub file_size: u64,
}

pub struct FileToDownload {
    pub file_path: String,
    pub file_owner: String,
}

pub fn get_everything_file(config: &Config, display_name: &String) -> SharedFile {
    // The "root" everything directory
    let mut everything_file: SharedFile = SharedFile {
        path: "everything/".to_string(),
        is_directory: true,
        files: Vec::new(),
        file_size: 0,
    };

    // Get SharedFiles
    for file in &config.shared_files {
        if file.shared_with.contains(&display_name) == false {
            continue;
        }

        let path: String = file.path.clone();
        let is_directory: bool = metadata(&path).unwrap().is_dir();

        let mut file_size: u64 = 0; // directory size calculated by all files
        if is_directory == false {
            file_size = metadata(&path).unwrap().len();
        }

        let mut shared_file: SharedFile = SharedFile {
            path,
            is_directory,
            files: Vec::new(),
            file_size,
        };
        process_shared_file(&mut shared_file);
        everything_file.file_size += shared_file.file_size;
        everything_file.files.push(shared_file);
    }

    return everything_file;
}

pub fn process_shared_file(shared_file: &mut SharedFile) {
    if shared_file.is_directory == false {
        return;
    }

    let transmitic_path = crate::config::get_path_transmitic_config_dir().to_str().unwrap().to_string();
    if shared_file.is_directory {
        for file in fs::read_dir(&shared_file.path).unwrap() {
            let file = file.unwrap();
            let path = file.path();
            let path_string = String::from(path.to_str().unwrap());

            if path_string.contains(&transmitic_path) {
                continue;
            }

            let is_directory = path.is_dir();

            let mut file_size: u64 = 0; // directory size calculated by all files
            if is_directory == false {
                file_size = metadata(&path_string).unwrap().len();
            }
            let mut new_shared_file = SharedFile {
                path: path_string,
                is_directory,
                files: Vec::new(),
                file_size,
            };
            if is_directory {
                process_shared_file(&mut new_shared_file);
            }
            shared_file.file_size += new_shared_file.file_size;
            shared_file.files.push(new_shared_file);
        }
    }
}

// FIXME - how to handle files with invalid file names?
pub fn remove_invalid_files(shared_file: &mut SharedFile, client_display_name: &String) {
    if shared_file.is_directory {
        shared_file.files.retain(|x|file_contains_valid_chars(&x));

        for s in shared_file.files.iter_mut() {
            remove_invalid_files(s, client_display_name);
        }
    }
}

fn file_contains_valid_chars(shared_file: &SharedFile) -> bool {
    let blocked_chars = get_blocked_file_name_chars();
    for c in blocked_chars.chars() {
        if shared_file.path.contains(c) == true {
            println!("WARNING: Rejecting file that contains invalid char '{}'", c);
            return false;        
        }
    }
    return true;
}

pub fn print_shared_files(shared_file: &SharedFile, spacer: &String) {
    let file_size_string = get_file_size_string(shared_file.file_size);

    let mut ftype = "file";
    if shared_file.is_directory {
        ftype = "dir";
    }

    println!(
        "{}{} | ({}) ({})",
        spacer, shared_file.path, file_size_string, ftype
    );
    if shared_file.is_directory {
        let mut new_spacer = spacer.clone();
        new_spacer.push_str("    ");
        for sub_file in &shared_file.files {
            print_shared_files(&sub_file, &new_spacer);
        }
    }
}
