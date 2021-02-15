
use crate::utils::{exit_error, get_blocked_display_name_chars, get_blocked_file_name_chars};
use crate::crypto_ids;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::{path::PathBuf, sync::Arc};
use std::env;
extern crate base64;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
	pub my_private_id: String,
	pub trusted_users_public_ids: Vec<TrustedUser>,
	pub shared_files: Vec<ConfigSharedFile>,
	pub server_port: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigSharedFile {
	pub path: String,
	pub shared_with: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustedUser {
	pub public_id: String,
	pub display_name: String,
	pub ip_address: String,
	pub port: String,
	pub enabled: bool,
}


pub fn verify_config(config: &Config) {
	let blocked_file_name_chars = get_blocked_file_name_chars();
	let blocked_extended = get_blocked_display_name_chars();

	// public ids display name is valid
	for key in &config.trusted_users_public_ids {
		for c in blocked_extended.chars() {
			if key.display_name.contains(c) == true {
				exit_error(format!("public id display name '{}' from config.json contains char '{}'. The following are not allowed '{}'", key.display_name, c, blocked_extended));
			}
		}
	}

	// duplicate public id display names
	for key in &config.trusted_users_public_ids {
		let mut count = 0;
		for keyj in &config.trusted_users_public_ids {
			if keyj.display_name == key.display_name {
				count += 1;
			}
		}
		if count > 1 {
			exit_error(format!(
				"Public ID display name '{}' appears '{}' times. It can only be used once.",
				key.display_name, count
			));
		}
	}

	// shared file valid file names
	for f in &config.shared_files {
		for c in blocked_file_name_chars.chars() {
			if f.path.contains(c) == true {
				exit_error(format!("Shared file path '{}' from config.json contains char '{}'. The following are not allowed '{}'", f.path, c, blocked_file_name_chars));
			}
		}
	}

	// shared files exist
	for f in &config.shared_files {
		if Path::new(&f.path).exists() == false {
			exit_error(format!("Shared file in config doesn't exist: '{}'", f.path));
		}
	}

	// don't allow transmitic config
	let transmitic_path = get_path_transmitic_config_dir().to_str().unwrap().to_string();
	for f in &config.shared_files {
		if f.path.contains(&transmitic_path) {
			exit_error(format!("Cannot share the Transmitic configuration folder, or a file in it. {} ", f.path));
		}
	}

	// Shared With is valid
	let mut display_names: Vec<String> = Vec::new();
	for key in &config.trusted_users_public_ids {
		display_names.push(key.display_name.clone());
	}
	for f in &config.shared_files {
		for name in f.shared_with.iter() {
			if display_names.contains(name) == false {
				exit_error(format!(
					"Shared file '{}' is shared with '{}', which isn't found in the config.json",
					f.path, name
				));
			}
		}
	}
}


pub fn create_config_dir() {
	let path = get_path_transmitic_config_dir();
	println!("Transmitic Config Dir: {:?}", path);
	fs::create_dir_all(path).unwrap();
}

pub fn get_path_transmitic_config_dir() -> PathBuf {
	let mut path = env::current_exe().unwrap();
	path.pop();
	path.push("transmitic_config");
	return path;
}

pub fn get_path_downloads_dir() -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push("downloads");
	return path;
}

pub fn get_path_downloads_dir_user(user: &String) -> PathBuf {
	let mut path = get_path_downloads_dir();
	path.push(user);
	return path;
}

pub fn get_path_download_queue(user: &TrustedUser) -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push(format!("download_queue_{}.txt", user.display_name));
	return path;
}

pub fn delete_download_queue_file(user: &TrustedUser) {
	let file_path = get_path_download_queue(user);
	if file_path.exists() == true {
		fs::remove_file(file_path).unwrap();
	}
}

pub fn get_path_config_json() -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push("transmitic_config.json");
	return path;
}

pub fn get_path_my_config_dir() -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push("my_config");
	return path;
}

pub fn get_path_users_public_ids_dir() -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push("users_public_ids");
	return path;
}


pub fn get_path_user_public_id_file(file_name: &String) -> PathBuf {
	let mut path = get_path_users_public_ids_dir();
	path.push(file_name);
	return path;
}

pub fn init_config() -> bool {
	let config_path = get_path_config_json();
	println!("config path: {:?}", config_path);

	if !config_path.exists() {
		create_new_config();
		return true;
	}

	return false;
}

pub fn create_new_config() {

	let (private_id_bytes, public_id_bytes) = crypto_ids::generate_id_pair();

	let private_id_string = base64::encode(private_id_bytes);

	let empty_config: Config = Config{
	    my_private_id: private_id_string,
	    trusted_users_public_ids: Vec::new(),
	    shared_files: Vec::new(),
	    server_port: "7878".to_string(),
	};

	write_config(&empty_config);
}

pub fn write_config(config: &Config) {
	let config_path = get_path_config_json();
	let empty_config_str = serde_json::to_string(&config).unwrap();
	fs::write(config_path, empty_config_str).unwrap();
}

pub fn get_config() -> Config {
	let config_path = get_path_config_json();
	if config_path.exists() == false {
		exit_error(format!(
			"config.json does not exist at '{}'",
			config_path.to_str().unwrap()
		));
	}
	let config_string = fs::read_to_string(&config_path).unwrap();
	let config = match serde_json::from_str(&config_string.clone()) {
		Ok(c) => c,
		Err(e) => {
			println!("{:?}", e);
			exit_error(format!(
				"config.json is invalid '{}'",
				config_path.to_str().unwrap()
			));
		}
	};
	return config;
}

