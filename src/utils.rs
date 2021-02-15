use serde::{Deserialize, Serialize};
use std::fs::metadata;
use std::{panic, process, thread, time};
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
struct FilesJson {
	files: Vec<PathJson>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PathJson {
	path: String,
}

pub fn get_size_of_directory(path: &str) -> usize {
	let mut size: usize = 0;
	for entry in fs::read_dir(path).unwrap() {
		let entry = entry.unwrap();
		let path = entry.path();
		let path_str = path.to_str().unwrap();
		if path.is_dir() {
			size += get_size_of_directory(path_str);
		} else {
			size += metadata(path_str).unwrap().len() as usize;
		}
	}

	return size;
}

pub fn get_blocked_file_name_chars() -> String {
	return String::from("{};*?'\"<>|");
}

pub fn get_blocked_display_name_chars() -> String {
	let mut chars = get_blocked_file_name_chars();
	chars.push_str("/\\[]()");
	return chars;
}

pub fn get_file_size_string(mut bytes: u64) -> String {
	let gig: u64 = 1_000_000_000;
	let meg: u64 = 1_000_000;
	let byte: u64 = 1000;

	let divisor: u64;
	let unit: String;

	if bytes == 0 {
		bytes = 1;
		divisor = 1;
		unit = "b".to_string();
	} else if bytes >= gig {
		divisor = gig;
		unit = "GB".to_string();
	} else if bytes >= meg {
		divisor = meg;
		unit = "MB".to_string();
	} else if bytes >= byte {
		divisor = byte;
		unit = "KB".to_string();
	} else {
		divisor = byte;
		unit = "b".to_string();
	}

	let size = bytes as f64 / divisor as f64;
	let mut size_string = String::from(format!("{:.2}", size));
	size_string.push_str(" ");
	size_string.push_str(&unit);
	return size_string;
}

pub fn exit_error(msg: String) -> ! {
	println!("\n!!!! ERROR: {}", msg);
	println!("Transmitic has stopped");
	process::exit(1);
}
