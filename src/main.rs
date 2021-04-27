mod shared_file;
mod utils;
mod config;
mod crypto_ids;

use shared_file::{
	SharedFile,
	FileToDownload,
	get_everything_file,
	remove_invalid_files,
	print_shared_files,
};
use config::{
	TrustedUser,
	get_path_transmitic_config_dir,
	get_path_my_config_dir,
	get_path_user_public_id_file,
	Config,
	create_config_dir,
	verify_config,
	get_config,
	init_config,
	
};
use utils::{
	get_size_of_directory,
	exit_error,
	get_file_size_string,
};

use sciter::{dispatch_script_call, host::{LOAD_RESULT, SCN_LOAD_DATA}, request::Request, s2w};
use sciter::Value;

extern crate sciter;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, net::{IpAddr, Ipv4Addr}, process::Command, sync::MutexGuard};
use std::env;
use std::fs;
use std::fs::metadata;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::str;
use std::sync::Mutex;
use std::{collections::HashMap, net::SocketAddr};
use std::{panic, process, thread, time};
use std::{path::PathBuf, sync::Arc};

// CRYPTO
extern crate x25519_dalek;
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

use rand_core::OsRng;
use ring::{
	rand,
	signature::{self, KeyPair},
};
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

const MSG_TYPE_SIZE: usize = 1;
const PAYLOAD_SIZE_LEN: usize = 4;

const MSG_FILE_LIST: u8 = 1;
const MSG_FILE_LIST_PIECE: u8 = 2;
const MSG_FILE_LIST_FINAL: u8 = 3;

const MSG_FILE_CHUNK: u8 = 4;
const MSG_FILE_FINISHED: u8 = 5;

const MSG_FILE_INVALID_FILE: u8 = 6;
const MSG_CANNOT_SELECT_DIRECTORY: u8 = 7;
const MSG_FILE_SELECTION_CONTINUE: u8 = 8; // TODO Only use CONTINUE?

const MSG_CLIENT_DIFFIE_PUBLIC: u8 = 9;
const MSG_SERVER_DIFFIE_PUBLIC: u8 = 10;

const MAX_DATA_SIZE: usize = 100_000;
const TOTAL_BUFFER_SIZE: usize = MSG_TYPE_SIZE + PAYLOAD_SIZE_LEN + MAX_DATA_SIZE;
const TOTAL_CRYPTO_BUFFER_SIZE: usize = TOTAL_BUFFER_SIZE + 16;
const PAYLOAD_OFFSET: usize = MSG_TYPE_SIZE + PAYLOAD_SIZE_LEN;

const VERSION: &str = "0.3.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic In Development Alpha";



struct SecureStream<'a> {
	tcp_stream: &'a TcpStream,
	nonce: [u8; 12],
	cipher: Aes256Gcm,
	crypto_buffer: [u8; TOTAL_CRYPTO_BUFFER_SIZE],
	buffer: [u8; TOTAL_BUFFER_SIZE],
}

impl<'a> SecureStream<'a> {
	fn new(tcp_stream: &'a TcpStream, cipher: Aes256Gcm) -> SecureStream<'a> {
		SecureStream {
			tcp_stream,
			nonce: [0; 12],
			cipher,
			crypto_buffer: [0; TOTAL_CRYPTO_BUFFER_SIZE],
			buffer: [0; TOTAL_BUFFER_SIZE],
		}
	}

	fn increment_nonce(&mut self) {
		let mut flip: bool;
		for i in 0..self.nonce.len() {
			let byte = self.nonce[i];
			// TODO once this maxes out, we have to reset connection
			if byte >= 255 {
				if i == self.nonce.len() - 1 {
					panic!("ERROR: Nonce maxed. Reconnect.");
				}
				self.nonce[i] = 0;
				flip = true;
			} else {
				self.nonce[i] += 1;
				flip = false;
			}

			if flip == false {
				break;
			}
		}
	}

	fn read(&mut self) {
		self._read_stream();
		let new_nonce = GenericArray::from_slice(&self.nonce[..]);
		let plaintext = self
			.cipher
			.decrypt(new_nonce, self.crypto_buffer.as_ref())
			.unwrap();
		&mut self.buffer.copy_from_slice(&plaintext[..TOTAL_BUFFER_SIZE]);
		self.increment_nonce();
	}

	fn _read_stream(&mut self) {
		self.tcp_stream.read_exact(&mut self.crypto_buffer).unwrap();
	}

	fn write(&mut self, msg: u8, payload: &Vec<u8>) {
		set_buffer(&mut self.buffer, msg, payload);
		let new_nonce = GenericArray::from_slice(&self.nonce[..]);
		let cipher_text = self
			.cipher
			.encrypt(new_nonce, self.buffer.as_ref())
			.unwrap();

		self._write_stream(&cipher_text[..]);
		self.increment_nonce();
	}

	fn _write_stream(&mut self, buffer: &[u8]) {
		self.tcp_stream.write_all(buffer).unwrap();
		self.tcp_stream.flush().unwrap();
	}
}


struct SingleConnection {
	should_reset: bool,
}


struct IncomingConnection {
	user: TrustedUser,
	active_download: Option<SharedFile>,
	active_download_percent: usize,
	active_download_current_bytes: f64,
	is_downloading: bool,
	finished_downloads: Vec<String>,
	is_disabled: bool,
	single_connections: Vec<Arc<Mutex<SingleConnection>>>,
}

struct OutgoingConnection {
	user: TrustedUser,
	download_queue: VecDeque<String>,
	finished_downloads: Vec<(String, String)>,
	invalid_downloads: Vec<String>,
	root_file: Option<SharedFile>,
	active_download: Option<SharedFile>,
	active_download_percent: usize,
	active_download_current_bytes: f64,
	is_online: bool,
	is_deleted: bool,
	should_reset_connection: bool,
	stop_active_download: bool,
	is_paused: bool,
}

impl OutgoingConnection {
	pub fn new(user: TrustedUser, is_all_paused: bool) -> OutgoingConnection {
		let queue_path = config::get_path_download_queue(&user);
		let mut download_queue: VecDeque<String> = VecDeque::new();
		if queue_path.exists() {
			let f = fs::read_to_string(queue_path).expect("Unable to read file");
			for mut line in f.lines() {
				line = line.trim();
				if line != "" {
					download_queue.push_back(line.to_string());
				}
			}
		}

		OutgoingConnection {
			user: user,
			download_queue: download_queue,
			finished_downloads: Vec::new(),
			invalid_downloads: Vec::new(),
			root_file: None,
			active_download: None,
			active_download_percent: 0,
			active_download_current_bytes: 0.0,
			is_online: false,
			is_deleted: false,
			should_reset_connection: false,
			stop_active_download: false,
			is_paused: is_all_paused,
		}
	}


	pub fn download_file(&mut self, file_path: String) {
		println!(
			"DOWNLOAD FILE FOR: {} - {}",
			self.user.display_name, file_path
		);

		&self.download_queue.push_back(file_path);
		self.write_queue();
	}

	fn write_queue(&self) {
		let mut write_string = String::new();

		if let Some(shared_file) = &self.active_download {
			write_string.push_str(&format!("{}\n", &shared_file.path));
		}

		for f in &self.download_queue {
			write_string.push_str(&format!("{}\n", &f));
		}

		let file_path = config::get_path_download_queue(&self.user);
		let mut f = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.open(file_path)
			.unwrap();
		f.write(write_string.as_bytes()).unwrap();
	}
}

fn handle_outgoing(
	outgoing_connection: &Arc<Mutex<OutgoingConnection>>,
	local_key_pair_bytes: &Vec<u8>,
) {
	let mut connection_guard = outgoing_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
	let local_key_pair =
		signature::Ed25519KeyPair::from_pkcs8(local_key_pair_bytes.as_ref()).unwrap();
	let mut remote_addr = String::from(&connection_guard.user.ip_address);
	remote_addr.push_str(&format!(":{}", &connection_guard.user.port));

	println!(
		"Handle Outgoing {} - {}",
		remote_addr, &connection_guard.user.display_name
	);

	//	move into struct?
	let remote_socket_addr: SocketAddr = remote_addr.parse().unwrap();
	let stream = match TcpStream::connect_timeout(&remote_socket_addr, time::Duration::from_millis(1000)) {
		Ok(s) => s,
		Err(e) => {
			println!("Could not connect to '{}': {:?}", remote_addr, e);
			return;
		}
	};
	let cipher = get_local_to_outgoing_secure_stream_cipher(
		&stream,
		&local_key_pair,
		connection_guard.user.public_id.clone(),
	);
	let mut secure_stream: SecureStream = SecureStream::new(&stream, cipher);

	connection_guard.root_file = Some(request_file_list(
		&mut secure_stream,
		&connection_guard.user.display_name,
	));
	connection_guard.is_online = true;
	std::mem::drop(connection_guard);

	loop {
		let mut connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());

		if connection_guard.is_deleted == true {
			println!("Outgoing Connection deleted. {}", connection_guard.user.display_name);
			std::mem::drop(connection_guard);
			break;
		}

		if connection_guard.should_reset_connection == true {
			println!("Outgoing Connection reset. {}", connection_guard.user.display_name);
			std::mem::drop(connection_guard);
			break;
		}

		if connection_guard.is_paused == true {
			std::mem::drop(connection_guard);
			thread::sleep(time::Duration::from_secs(3));
			continue;
		}

		let current_download_file = connection_guard.download_queue.get(0);
		match current_download_file {
			Some(file_path) => {
				let mut file_path = file_path.clone();
				println!(
					"PRE DOWNLOAD: {} - {} - {:?}",
					connection_guard.user.display_name, file_path, connection_guard.root_file
				);
				let remote_user_name = connection_guard.user.display_name.clone();
				file_path = file_path.replace("\\\\", "\\");
				let shared_file =
					get_file_by_path(&file_path, &connection_guard.root_file.clone().unwrap());
				
				if let None = shared_file {
					println!("Invalid download: {}", file_path);
					connection_guard.invalid_downloads.push(file_path);
					connection_guard.download_queue.pop_front();
					connection_guard.write_queue();
					connection_guard.active_download = None;
					std::mem::drop(connection_guard);
					continue;
				}

				let shared_file = shared_file.unwrap();
				connection_guard.stop_active_download = false;
				connection_guard.active_download_percent = 0;
				connection_guard.active_download_current_bytes = 0.0;
				connection_guard.active_download = Some(shared_file.clone());
				std::mem::drop(connection_guard);
				client_download_from_remote(
					&mut secure_stream,
					&shared_file,
					&remote_user_name,
					outgoing_connection,
				);
				let mut connection_guard = outgoing_connection
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
				if connection_guard.should_reset_connection == true || connection_guard.is_deleted == true {
					std::mem::drop(connection_guard);
					return;
				}

				if connection_guard.is_paused == true {
					std::mem::drop(connection_guard);
					continue;
				}

				connection_guard.active_download = None;
				
				if connection_guard.stop_active_download == false {
					if shared_file.is_directory {
						// FIXME copied from download_shared_file
						let destination_path = config::get_path_downloads_dir_user(&remote_user_name);
						let mut destination_path = destination_path.into_os_string().to_str().unwrap().to_string();
						destination_path.push_str("/");
						let current_path_obj = Path::new(&shared_file.path);
						let current_path_name = current_path_obj.file_name().unwrap().to_str().unwrap();
						destination_path.push_str(current_path_name);
						connection_guard.finished_downloads.push((shared_file.path, destination_path));
					}
				}
				
				// Cancelling all downloads clears the queue
				if connection_guard.download_queue.is_empty() == false {
					connection_guard.download_queue.pop_front();
				}
				connection_guard.write_queue();
				std::mem::drop(connection_guard);
			}
			None => {
				std::mem::drop(connection_guard);
				thread::sleep(time::Duration::from_millis(1000));
			}
		}
	}
}

fn get_local_to_outgoing_secure_stream_cipher(
	mut stream: &TcpStream,
	local_key_pair: &signature::Ed25519KeyPair,
	remote_public_id: String,
) -> Aes256Gcm {
	let local_diffie_secret = EphemeralSecret::new(OsRng);
	let local_diffie_public = PublicKey::from(&local_diffie_secret);
	let local_diffie_public_bytes: &[u8; 32] = local_diffie_public.as_bytes();
	let local_diffie_signature_public_bytes = local_key_pair.sign(local_diffie_public_bytes);
	let local_diffie_signed_public_bytes = local_diffie_signature_public_bytes.as_ref();
	// Send remote the local's diffie public key
	let mut buffer = [0; TOTAL_BUFFER_SIZE];
	let mut diffie_payload: Vec<u8> = Vec::with_capacity(32 + 64); // diffie public key + signature
	for byte in local_diffie_public_bytes {
		diffie_payload.push(byte.clone());
	}

	for byte in local_diffie_signed_public_bytes {
		diffie_payload.push(byte.clone());
	}

	set_buffer(&mut buffer, MSG_CLIENT_DIFFIE_PUBLIC, &diffie_payload);
	stream.write_all(&mut buffer).unwrap();
	stream.flush().unwrap();

	// Read remote diffie public
	stream.read_exact(&mut buffer).unwrap();
	let mut remote_diffie_public_bytes: [u8; 32] = [0; 32];
	remote_diffie_public_bytes.copy_from_slice(&buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 32]);

	let mut remote_diffie_signed_public_bytes: [u8; 64] = [0; 64];
	remote_diffie_signed_public_bytes
		.copy_from_slice(&buffer[PAYLOAD_OFFSET + 32..PAYLOAD_OFFSET + 32 + 64]);

	let remote_public_key_bytes = crypto_ids::get_bytes_from_base64_str(&remote_public_id);
	let remote_public_key =
		signature::UnparsedPublicKey::new(&signature::ED25519, remote_public_key_bytes);
	
	let client_connecting_addr = stream.peer_addr().unwrap();
	let client_connecting_ip = client_connecting_addr.ip().to_string();
	match remote_public_key
		.verify(
			&remote_diffie_public_bytes,
			&remote_diffie_signed_public_bytes,
		) {
			Err(_) => {
				panic!(format!("ERROR: Remote signature failure. Verify Public ID is correct for {}", client_connecting_ip));
			}
			_ => {}
		}

	// Create encryption key
	let remote_diffie_public_key = PublicKey::from(remote_diffie_public_bytes);
	let local_shared_secret = local_diffie_secret.diffie_hellman(&remote_diffie_public_key);
	let encryption_key = local_shared_secret.as_bytes();
	let key = GenericArray::from_slice(&encryption_key[..]);
	// Create AES and stream
	let cipher = Aes256Gcm::new(key);
	return cipher;
}

fn client_download_from_remote(
	secure_stream: &mut SecureStream,
	download_file: &SharedFile,
	remote_user_name: &String,
	outgoing_connection: &Arc<Mutex<OutgoingConnection>>,
) {

	let root_download_dir = config::get_path_downloads_dir_user(remote_user_name);
	let mut root_download_dir = root_download_dir.into_os_string().to_str().unwrap().to_string();
	root_download_dir.push_str("/");
	println!("Download start: {:?}", download_file);
	download_shared_file(
		secure_stream,
		&download_file,
		&root_download_dir,
		false,
		outgoing_connection,
		&root_download_dir,
	);
}

fn get_file_by_path(file_choice: &str, shared_file: &SharedFile) -> Option<SharedFile> {
	if shared_file.path == file_choice {
		return Some(shared_file.clone());
	}

	for a_file in &shared_file.files {
		if let Some(found) =  get_file_by_path(file_choice, &a_file) {
			return Some(found.clone());
		}
	}

	return None;
}

fn download_shared_file(
	secure_stream: &mut SecureStream,
	shared_file: &SharedFile,
	download_dir: &String,
	continue_downloading_in_progress: bool,
	outgoing_connection: &Arc<Mutex<OutgoingConnection>>,
	root_download_dir: &String,
) {
	let current_path_obj = Path::new(&shared_file.path);
	let current_path_name = current_path_obj.file_name().unwrap().to_str().unwrap();

	if shared_file.is_directory {
		let mut new_download_dir = String::from(download_dir);
		new_download_dir.push_str(current_path_name);
		new_download_dir.push_str(&"/".to_string());
		for a_file in &shared_file.files {
			download_shared_file(
				secure_stream,
				a_file,
				&new_download_dir,
				continue_downloading_in_progress,
				outgoing_connection,
				root_download_dir,
			);
					
			let conn = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
			
			if conn.is_deleted == true {
				println!("Connection deleted mid DIR download. {}", conn.user.display_name);
				std::mem::drop(conn);
				return;
			}
			
			if conn.should_reset_connection == true {
				println!("Connection reset mid DIR download. {}", conn.user.display_name);
				std::mem::drop(conn);
				return;
			}

			if conn.stop_active_download == true {
				println!("Active download cancelled mid DIR download. {}", conn.user.display_name);
				std::mem::drop(conn);
				return;
			}

			std::mem::drop(conn);
		}
	} else {
		// Create directory for file download
		fs::create_dir_all(&download_dir).unwrap();
		let mut destination_path = download_dir.clone();
		destination_path.push_str(current_path_name);
		println!("Saving to: {}", destination_path);

		// Send selection to server
		println!("Sending selection to server");
		let selection_msg: u8;
		let selection_payload: Vec<u8>;
		let file_length: u64;
		if Path::new(&destination_path).exists() {
			file_length = metadata(&destination_path).unwrap().len();
		} else {
			file_length = 0;
		}
		let mut file_continue_payload = file_length.to_be_bytes().to_vec();
		file_continue_payload.extend_from_slice(&shared_file.path.as_bytes());
		selection_msg = MSG_FILE_SELECTION_CONTINUE;
		selection_payload = file_continue_payload;
		secure_stream.write(selection_msg, &selection_payload);

		// Check first response for error
		secure_stream.read();
		let mut server_msg: u8 = secure_stream.buffer[0];
		println!("Initial download response: {}", server_msg);

		if server_msg == MSG_FILE_INVALID_FILE {
			println!("!!!! ERROR: Invalid file selection");
			let mut conn = outgoing_connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			conn.invalid_downloads.push(shared_file.path.clone());
			std::mem::drop(conn);
			return;
		}

		if server_msg == MSG_CANNOT_SELECT_DIRECTORY {
			panic!("!!!! ERROR: Cannot download directory");
		}

		if server_msg != MSG_FILE_CHUNK {
			panic!("!!!! ERROR: Expected MSG_FILE_CHUNK, got: {}", server_msg);
		}

		if server_msg == MSG_FILE_FINISHED {
			println!(
				"Download complete. Nothing left to download. {}",
				destination_path
			);
			return;
		}

		// Valid file, download it
		let mut current_downloaded_bytes: usize;
		let mut f: File;
		// TODO use .create() and remove else?
		if Path::new(&destination_path).exists() {
			f = OpenOptions::new()
				.write(true)
				.open(&destination_path)
				.unwrap();
			f.seek(SeekFrom::End(0)).unwrap();
			current_downloaded_bytes = metadata(&destination_path).unwrap().len() as usize;
		} else {
			f = File::create(&destination_path).unwrap();
			current_downloaded_bytes = 0;
		}
		// TODO Inefficient. Every download recalculates dir size
		let mut conn = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());

		// TODO send server message that mid download is cancelled
		if conn.is_deleted == true {
			println!("Connection deleted mid download. {}", conn.user.display_name);
			std::mem::drop(conn);
			return;
		}
		
		if conn.should_reset_connection == true {
			println!("Connection reset mid download. {}", conn.user.display_name);
			std::mem::drop(conn);
			return;
		}

		if conn.stop_active_download == true {
			println!("Active download cancelled. {}", conn.user.display_name);
			std::mem::drop(conn);
			return;
		}
		
		if conn.active_download.as_ref().unwrap().is_directory {
			let _path_obj = Path::new(&conn.active_download.as_ref().unwrap().path);
			let _path_name = _path_obj.file_name().unwrap().to_str().unwrap();

			let mut dldir = String::from(root_download_dir);
			dldir.push_str("/");
			dldir.push_str(_path_name);
			conn.active_download_current_bytes = get_size_of_directory(&dldir) as f64;
		} else {
			conn.active_download_current_bytes = current_downloaded_bytes as f64;
		}
		std::mem::drop(conn);

		loop {
			let actual_payload_size = get_payload_size_from_buffer(&secure_stream.buffer);
			current_downloaded_bytes += actual_payload_size;
			f.write(&secure_stream.buffer[PAYLOAD_OFFSET..actual_payload_size + PAYLOAD_OFFSET])
				.unwrap();
			secure_stream.read();
			server_msg = secure_stream.buffer[0];

			let mut conn = outgoing_connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());

			if conn.is_deleted == true {
				println!("Connection deleted in download. {}", conn.user.display_name);
				std::mem::drop(conn);
				return;
			}

			if conn.should_reset_connection == true {
				println!("Connection reset in download. {}", conn.user.display_name);
				std::mem::drop(conn);
				return;
			}

			if conn.stop_active_download == true {
				println!("Active download cancelled in download. {}", conn.user.display_name);
				std::mem::drop(conn);
				return;
			}
			
			conn.active_download_current_bytes += actual_payload_size as f64;
			conn.active_download_percent = ((conn.active_download_current_bytes as f64
				/ conn.active_download.clone().unwrap().file_size as f64)
				* (100 as f64)) as usize;
			std::mem::drop(conn);

			if server_msg == MSG_FILE_FINISHED {
				break;
			}
			if server_msg != MSG_FILE_CHUNK {
				panic!("Expected MSG_FILE_CHUNK, got {}", server_msg);
			}
		}

		let mut conn = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		//conn.active_download_percent = 0;
		//conn.active_download = None;
		conn.finished_downloads.push((shared_file.path.clone(), destination_path.clone()));
		std::mem::drop(conn);
		println!("100%\nDownload finished: {}", destination_path);
	}
}

struct OutgoingConnectionManager {
	config: Arc<Mutex<Config>>,
	outgoing_connections: HashMap<String, Arc<Mutex<OutgoingConnection>>>,
	is_all_paused: bool,
}

fn handle_outgoing_forever(
	outgoing_connection: &Arc<Mutex<OutgoingConnection>>,
	local_key_data: Arc<Mutex<LocalKeyData>>,
) {
	loop {
		let mut connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		if connection_guard.is_deleted == true {
			println!("Outgoing Forever Connection deleted. {}", connection_guard.user.display_name);
			std::mem::drop(connection_guard);
			break;
		}
		if connection_guard.download_queue.is_empty() {
			std::mem::drop(connection_guard);
			thread::sleep(time::Duration::from_millis(1000));
			continue;
		}
		connection_guard.should_reset_connection = false;
		std::mem::drop(connection_guard);
		
		let local_key_data_guard = local_key_data
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let local_key_pair_bytes_clone = local_key_data_guard.local_key_pair_bytes.clone();
		std::mem::drop(local_key_data_guard);

		let _ = panic::catch_unwind(|| {
			handle_outgoing(outgoing_connection, &local_key_pair_bytes_clone);
		});
		std::mem::drop(outgoing_connection);
		let mut connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard.is_online = false;
		if connection_guard.is_deleted == true {
			println!("Connection deleted. {}", connection_guard.user.display_name);
			std::mem::drop(connection_guard);
			break;
		}
		std::mem::drop(connection_guard);
		println!("Error. Reconnecting...");
		thread::sleep(time::Duration::from_millis(10000));
	}
}

impl OutgoingConnectionManager {
	pub fn new(config: Arc<Mutex<Config>>, local_key_data: Arc<Mutex<LocalKeyData>>, is_all_paused: bool) -> OutgoingConnectionManager {
		let mut connections: HashMap<String, Arc<Mutex<OutgoingConnection>>> = HashMap::new();
		
		let config_guard = config			
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		for user in config_guard.trusted_users_public_ids.iter() {
			let outgoing_connection = OutgoingConnection::new(user.clone(), is_all_paused);
			let outgoing_connection_arc = Arc::new(Mutex::new(outgoing_connection));
			let outgoing_connection_arc_clone = Arc::clone(&outgoing_connection_arc);
			let outgoing_connection_arc_clone2 = Arc::clone(&outgoing_connection_arc);
			connections.insert(user.display_name.clone(), outgoing_connection_arc_clone2);
			let thread_name = user.display_name.clone();
			
			let local_key_data_arc = Arc::clone(&local_key_data);

			thread::spawn(move || {
				handle_outgoing_forever(&outgoing_connection_arc_clone, local_key_data_arc);
				println!("Outgoing final exit {}", thread_name);
			});
		}
		std::mem::drop(config_guard);

		OutgoingConnectionManager {
			config: config,
			outgoing_connections: connections,
			is_all_paused: is_all_paused,
		}
	}

	pub fn download_files(&mut self, file_list: Vec<FileToDownload>) {
		for f in file_list {
			let owner = f.file_owner;
			let path = f.file_path;
			let mut conn = self
				.outgoing_connections
				.get(&owner)
				.unwrap()
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			conn.download_file(path);
		}
	}
}

struct LocalKeyData {
	local_key_pair: signature::Ed25519KeyPair,
	local_key_pair_bytes: Vec<u8>,
}

struct Handler {
	config: Arc<Mutex<Config>>,
	local_key_data: Arc<Mutex<LocalKeyData>>,
	outgoing_connection_manager: OutgoingConnectionManager,
	incoming_connections: Arc<Mutex<HashMap<String, Arc<Mutex<IncomingConnection>>>>>,
	is_first_start: bool,
	sharing_mode: Arc<Mutex<String>>
}

fn reset_all_connections(mut connection_guard: MutexGuard<IncomingConnection>) -> MutexGuard<IncomingConnection> {
	println!("Start reset all connections");
	for s in connection_guard.single_connections.iter_mut() {
		s.lock().unwrap().should_reset = true;
	}
	connection_guard.single_connections.clear();
	println!("End reset all connections");
	return connection_guard;
}


/// This is hack to get around loading CSS on htm pages with sciter
/// 1. I can't get a relative to path to load css in a frame page
/// 2. SC_LOAD_DATA works for loading files, but using a frame causes a crash
/// I don't have any more time to deal with this, so I inject the CSS into the page
fn inject_css_into_page(page: &str) -> String {
	let bytes = include_bytes!("style.css");
	let css_str = str::from_utf8(bytes).unwrap();
	let new_page = page.replace("/* AUTO CSS INJECTION */", css_str);
	return new_page;
}

fn finalize_htm_page(page_bytes: &[u8]) -> String {
	let page_str = str::from_utf8(page_bytes).unwrap();
	let page_str = inject_css_into_page(page_str);
	return page_str;
}

impl Handler {
	
	fn download_file_list(&mut self, file_list: Value) {
		let mut files_to_download: Vec<FileToDownload> = Vec::new();
		for v in file_list.values() {
			println!("{} -- {}", v[0].to_string(), v[1].to_string());
			files_to_download.push(FileToDownload {
				file_owner: v[0].to_string().replace("\"", ""),
				file_path: v[1].to_string().replace("\"", ""),
			});
		}

		self.outgoing_connection_manager
			.download_files(files_to_download);
	}

	fn set_sharing_mode(&mut self, sharing_mode: Value) -> Value {
		let sharing_mode = self.clean_sciter_string(sharing_mode);

		let mut sharing_guard = self.sharing_mode			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		sharing_guard.clear();
		sharing_guard.push_str(&sharing_mode);

		std::mem::drop(sharing_guard);

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		
		for (display_name, incoming_connection) in incoming_connections_guard.iter() {
			let mut connection_guard = incoming_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
			connection_guard = reset_all_connections(connection_guard);
			std::mem::drop(connection_guard);

		}

		std::mem::drop(incoming_connections_guard);

		let msg = format!("Sharing has been set to '{}'", sharing_mode);
		let response = self.get_msg_box_response(0, &msg);
		response
	}


	fn remove_file(&mut self, file_path: Value) -> Value {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");

		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		
		let mut shared_with_display_names = Vec::new();
		for f in config_guard.shared_files.iter() {
			if f.path == file_path {
				shared_with_display_names = f.shared_with.clone();
				break;
			}
		}

		config_guard.shared_files.retain(|x|*x.path != file_path);

		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		
		for (display_name, incoming_connection) in incoming_connections_guard.iter() {
			if shared_with_display_names.contains(display_name) == true {
				let mut connection_guard = incoming_connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
				connection_guard = reset_all_connections(connection_guard);
				std::mem::drop(connection_guard);
			}
		}

		std::mem::drop(incoming_connections_guard);

		let msg = format!("'{}' has been removed", file_path);
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn add_files(&mut self, file_paths: Value) -> Value {
		let mut code = 0;
		let mut msg = format!("Files have been added");
		let transmitic_path = config::get_path_transmitic_config_dir().to_str().unwrap().to_string();
		let mut new_files = Vec::new();
		for file_path in file_paths.into_iter() {
			
			let mut file_path = self.clean_sciter_string(file_path);
			file_path = file_path.replace("/", "\\");
			
			if file_path.contains(&transmitic_path) {
				code = 1;
				msg = String::from(format!("No files added. Cannot share the Transmitic configuration folder, or a file in it. {} ", transmitic_path));
				break;
			}
			
			let blocked_file_name_chars = utils::get_blocked_file_name_chars();
			for c in blocked_file_name_chars.chars() {
				if file_path.contains(c) == true {
					code = 1;
					msg = String::from(format!("No files added. Cannot share, '{}', since it contains the character: {} . The following are not allowed: {}", file_path, c, blocked_file_name_chars));
					break;
				}
			}

			let new_shared_file = config::ConfigSharedFile {
				path: file_path.clone(),
				shared_with: Vec::new(),
			};

			new_files.push(new_shared_file);
		}

		if code == 0 {
			let mut config_guard = self.config			
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());

			for f in new_files {
				
				let mut skip = false;
				for c in config_guard.shared_files.iter() {
					if c.path == f.path {
						skip = true;
					}
				}
				if skip {
					continue;
				}

				config_guard.shared_files.push(f);
			}

			config::write_config(&config_guard);
			std::mem::drop(config_guard);
		}

		
		let response = self.get_msg_box_response(code, &msg);
		response
	}

	fn remove_shared_with(&mut self, display_name: Value, file_path: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");
		let display_name = self.clean_sciter_string(display_name);

		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		
		for f in config_guard.shared_files.iter_mut() {
			if f.path == file_path {
				f.shared_with.retain(|x|*x != display_name);
				break;
			}
		}

		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
	
		let incoming_connection = incoming_connections_guard
		.get(&display_name)
		.unwrap();
	
		let mut connection_guard = incoming_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard = reset_all_connections(connection_guard);
		std::mem::drop(connection_guard);
		std::mem::drop(incoming_connections_guard);
	}

	fn add_user_to_file(&mut self, file_path: Value, display_name: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");
		let display_name = self.clean_sciter_string(display_name);

		// TODO verify dispaly_name is valid: allowed and exists in keys
		let mut config_guard = self.config
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for file in config_guard.shared_files.iter_mut() {
			if file.path == file_path {
				file.shared_with.push(display_name.clone());
				break;
			}
		}

		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
	
		let incoming_connection = incoming_connections_guard
		.get(&display_name)
		.unwrap();
	
		let mut connection_guard = incoming_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard = reset_all_connections(connection_guard);
		std::mem::drop(connection_guard);
		std::mem::drop(incoming_connections_guard);
	}

	fn remove_user(&mut self, display_name: Value) {
		let mut display_name: String = display_name.into_string();
		display_name = display_name[1..display_name.len()-1].to_string();
		
		let mut delete_index = 0;
		let mut cloned_user: Option<TrustedUser> = None;

		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for user in config_guard.trusted_users_public_ids.iter_mut() {
			if user.display_name == display_name {
				user.enabled = false;
				cloned_user = Some(user.clone());
				break;
			}
			delete_index += 1;
		}
		let found_cloned_user = cloned_user.unwrap();

		config_guard.trusted_users_public_ids.remove(delete_index);

		
		// -- Remove user from shared files
		for files in config_guard.shared_files.iter_mut() {
			files.shared_with.retain(|x| *x != display_name);
		}

		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		let mut incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		let incoming_connection = incoming_connections_guard
		.get(&display_name)
		.unwrap();

		let mut connection_guard = incoming_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		
		connection_guard.is_disabled = true;
		std::mem::drop(connection_guard);

		incoming_connections_guard.remove(&display_name);

		std::mem::drop(incoming_connections_guard);

		config::delete_download_queue_file(&found_cloned_user);

		let mut outgoing_connection = self.outgoing_connection_manager.outgoing_connections.get(&display_name).unwrap()
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		outgoing_connection.is_deleted = true;
		std::mem::drop(outgoing_connection);

		self.outgoing_connection_manager.outgoing_connections.remove(&display_name);
	}

	fn disable_user(&mut self, display_name: Value) {
		let mut display_name: String = display_name.into_string();
		display_name = display_name[1..display_name.len()-1].to_string();
		
		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for user in config_guard.trusted_users_public_ids.iter_mut() {
			if user.display_name == display_name {
				user.enabled = false;
			}
		}

		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		let incoming_connection = incoming_connections_guard
		.get(&display_name)
		.unwrap();

		let mut connection_guard = incoming_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard.is_disabled = true;
		std::mem::drop(connection_guard);
		std::mem::drop(incoming_connections_guard);
	}

	fn enable_user(&mut self, display_name: Value) {
		let mut display_name: String = display_name.into_string();
		display_name = display_name[1..display_name.len()-1].to_string();
		
		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for user in config_guard.trusted_users_public_ids.iter_mut() {
			if user.display_name == display_name {
				user.enabled = true;
			}
		}

		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		let incoming_connection = incoming_connections_guard
		.get(&display_name)
		.unwrap();

		let mut connection_guard = incoming_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard.is_disabled = false;
		std::mem::drop(connection_guard);
		std::mem::drop(incoming_connections_guard);
	}

	fn get_msg_box_response(&self, code: i32, msg: &String) -> Value {
		let mut response = Value::new();
		response.push(Value::from(code));
		response.push(Value::from(msg));
		response
	}

	fn verify_inital_new_user_data(&self, display_name: &String, public_id: &String, ip_address: &String, port: &String) -> (i32, std::string::String) {
		// -- Display name
		// Chars
		if display_name.len() == 0 {
			return (1, "Nickname cannot be empty".to_string());
		}
		let blocked_chars = utils::get_blocked_display_name_chars();
		for c in display_name.chars() {
			if blocked_chars.contains(c) {
				let msg = format!("Nickname contains disallowed letter '{}'. These letters are not allowed: {}", c, blocked_chars);
				return (1, msg);
			}
		}

		// -- Public ID
		// Chars
		if public_id.len() == 0 {
			return (1, "Public ID cannot be empty".to_string());
		}
		// Valid Parse
		match base64::decode(&public_id) {
			Ok(_) => {},
			Err(e) => {
				let msg = format!("Invalid Public ID. Failed to decode. {}", e);
				return (1, msg);
			}
		}
		
		// -- Port
		// Chars
		if port.len() == 0 {
			return (1, "Port cannot be empty".to_string());
		}
		
		// -- IP Address
		// Chars
		if ip_address.len() == 0 {
			return (1, "IP Address cannot be empty".to_string());
		}
		// Valid Parse
		let ip_combo = format!("{}:{}", ip_address, port);
		let ip_parse: Result<SocketAddr, _> = ip_combo.parse();
		match ip_parse {
			Ok(_) => {},
			Err(e) => {
				let msg = format!("IP Address and port, {}, is not valid: {}", ip_combo, e);
				return (1, msg);
			}
		}

		return (0, "".to_string());
	}

	fn clear_finished_downloads(&mut self) -> Value {
		for (owner, mut outgoing_connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let mut outgoing_connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned|poisoned.into_inner());

			outgoing_connection_guard.finished_downloads.clear();

			std::mem::drop(outgoing_connection_guard);

		}

		let msg = format!("Finished Downloads have been cleared");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn clear_invalid_downloads(&mut self) -> Value {
		for (owner, mut outgoing_connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let mut outgoing_connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned|poisoned.into_inner());

			outgoing_connection_guard.invalid_downloads.clear();

			std::mem::drop(outgoing_connection_guard);

		}

		let msg = format!("Invalid Downloads have been cleared");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn pause_download(&mut self, display_name: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);

		let mut outgoing_connection = self.outgoing_connection_manager.outgoing_connections.get(&display_name).unwrap();
		let mut outgoing_connection_guard = outgoing_connection
		.lock()
		.unwrap_or_else(|poisoned|poisoned.into_inner());

		outgoing_connection_guard.is_paused = true;
		outgoing_connection_guard.stop_active_download = true;

		std::mem::drop(outgoing_connection_guard);

		let msg = format!("Downlods from '{}' will be paused", display_name);
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn pause_all_downloads(&mut self) -> Value {
		self.outgoing_connection_manager.is_all_paused = true;
		for (owner, mut outgoing_connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let mut outgoing_connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned|poisoned.into_inner());

			outgoing_connection_guard.is_paused = true;
			outgoing_connection_guard.stop_active_download = true;

			std::mem::drop(outgoing_connection_guard);
		}

		let msg = format!("All downloads will be paused");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn resume_all_downloads(&mut self) -> Value {
		for (owner, mut outgoing_connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let mut outgoing_connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned|poisoned.into_inner());

			outgoing_connection_guard.is_paused = false;

			std::mem::drop(outgoing_connection_guard);

		}

		self.outgoing_connection_manager.is_all_paused = false;

		let msg = format!("All downloads will be resumed");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn resume_download(&mut self, display_name: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);

		let mut outgoing_connection = self.outgoing_connection_manager.outgoing_connections.get(&display_name).unwrap();
		let mut outgoing_connection_guard = outgoing_connection
		.lock()
		.unwrap_or_else(|poisoned|poisoned.into_inner());

		outgoing_connection_guard.is_paused = false;

		std::mem::drop(outgoing_connection_guard);

		let msg = format!("Downloads from '{}' will be resumed", display_name);
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn cancel_download(&mut self, display_name: Value, file_path: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);
		let mut file_path = self.clean_sciter_string(file_path);

		let mut outgoing_connection = self.outgoing_connection_manager.outgoing_connections.get(&display_name).unwrap();
		let mut outgoing_connection_guard = outgoing_connection
		.lock()
		.unwrap_or_else(|poisoned|poisoned.into_inner());

		match &outgoing_connection_guard.active_download {
			Some(f) => {
				if f.path == file_path.replace("\\\\", "\\") {
					outgoing_connection_guard.stop_active_download = true;
					outgoing_connection_guard.active_download = None; // TODO is this needed?
				} else {
					outgoing_connection_guard.download_queue.retain(|x|x != &file_path);
					outgoing_connection_guard.write_queue();
				}
			}
			_ => {
				outgoing_connection_guard.download_queue.retain(|x|x != &file_path.replace("\\\\", "\\"));
				outgoing_connection_guard.write_queue();
			}
		}
		std::mem::drop(outgoing_connection_guard);

		let msg = format!("'{}' will be cancelled", file_path.replace("\\\\", "\\"));
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn cancel_all_downloads(&mut self) -> Value {
		for (owner, mut outgoing_connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let mut outgoing_connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned|poisoned.into_inner());

			match &outgoing_connection_guard.active_download {
				Some(f) => {
					//outgoing_connection_guard.active_download = None
					outgoing_connection_guard.stop_active_download = true;
					
				}
				_ => {
				}
			}
			outgoing_connection_guard.download_queue.clear();
			std::mem::drop(outgoing_connection_guard);

		}

		let msg = format!("All downloads will be cancelled");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn add_new_user(&mut self, display_name: Value, public_id: Value, ip_address: Value, port: Value) -> Value {

		
		let display_name = self.clean_sciter_string(display_name);
		let public_id = self.clean_sciter_string(public_id);
		let ip_address = self.clean_sciter_string(ip_address);
		let port = self.clean_sciter_string(port);

		// Initial check
		let (code, message ) = self.verify_inital_new_user_data(&display_name, &public_id, &ip_address, &port);
		if code != 0 {
			return self.get_msg_box_response(code, &message);
		}

		// -- Look for duplicates
		let config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let mut response_code = 0;
		let mut response_msg: String = String::from("");
		for user in config_guard.trusted_users_public_ids.iter() {
			if display_name == user.display_name {
				response_code = 1;
				response_msg = "Nickname already in use.".to_string();
				break;
			}

			if public_id == user.public_id {
				response_code = 1;
				response_msg = format!("Public ID already in use by {}", user.display_name);
				break;
			}

			if ip_address == user.ip_address {
				response_code = 1;
				response_msg = format!("IP Address already in use by {}", user.display_name);
				break;
			}
		}
		std::mem::drop(config_guard);

		if response_code == 0 {
			self.process_new_user(&display_name, &public_id, &ip_address, &port);
			response_msg = format!("User {} successfully added", &display_name);
		}
		
		
		let response = self.get_msg_box_response(response_code, &response_msg);
		response
	}

	fn edit_user(&mut self, current_display_name: Value, new_public_id: Value, new_ip: Value, new_port: Value) -> Value {

		let current_display_name = self.clean_sciter_string(current_display_name);
		let new_public_id = self.clean_sciter_string(new_public_id);
		let new_ip = self.clean_sciter_string(new_ip);
		let new_port = self.clean_sciter_string(new_port);

		println!("{}", current_display_name);
		println!("{}", new_public_id);
		println!("{}", new_ip);
		println!("{}", new_port);

		// Initial check
		let (code, message ) = self.verify_inital_new_user_data(&current_display_name, &new_public_id, &new_ip, &new_port);
		if code != 0 {
			return self.get_msg_box_response(code, &message);
		}

		// -- Look for duplicates
		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let mut response_code = 0;
		let mut response_msg: String = String::from("");
		for user in config_guard.trusted_users_public_ids.iter() {
			if current_display_name == user.display_name {
				continue;
			}

			if new_public_id == user.public_id {
				response_code = 1;
				response_msg = format!("Public ID already in use by {}", user.display_name);
				break;
			}

			if new_ip == user.ip_address {
				response_code = 1;
				response_msg = format!("IP Address already in use by {}", user.display_name);
				break;
			}
		}
		
		if response_code != 0 {
			std::mem::drop(config_guard);
			return self.get_msg_box_response(response_code, &response_msg);
		}

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		let incoming_connection = incoming_connections_guard
		.get(&current_display_name)
		.unwrap();

		let mut connection_guard = incoming_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		
		let mut outgoing_connection = self.outgoing_connection_manager.outgoing_connections.get(&current_display_name).unwrap()
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		/*
		- resets all connections
			- new id
			- local/internet
		*/
		// Modify existing user
		let mut new_trusted_user: Option<TrustedUser> = None;
		for user in config_guard.trusted_users_public_ids.iter_mut() {
			if current_display_name == user.display_name {
				user.ip_address = new_ip;
				user.port = new_port;
				user.public_id = new_public_id;
				new_trusted_user = Some(user.clone());
				break;
			}
		}
		config::write_config(&config_guard);
		let new_trusted_user = new_trusted_user.unwrap();
		response_msg = format!("User '{}' edited successfully", new_trusted_user.display_name);

		connection_guard.user = new_trusted_user.clone();
		outgoing_connection.user = new_trusted_user.clone();
		outgoing_connection.should_reset_connection = true;
		
		std::mem::drop(config_guard);
		std::mem::drop(connection_guard);
		std::mem::drop(incoming_connections_guard);
		std::mem::drop(outgoing_connection);

		let response = self.get_msg_box_response(response_code, &response_msg);
		response
	}

	fn clean_sciter_string(&self, s: Value) -> String {
		let mut s = s.to_string();
		s = s[1..s.len()-1].to_string();
		s = s.trim().to_string();
		s
	}

	fn process_new_user(&mut self, display_name: &String, public_id: &String, ip_address: &String, port: &String) {
		let new_user: config::TrustedUser = TrustedUser {
			public_id: public_id.clone(),
			display_name: display_name.clone(),
			ip_address: ip_address.clone(),
			port: port.clone(),
			enabled: true,
		};
		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		config_guard.trusted_users_public_ids.push(new_user.clone());
		config::write_config(&config_guard);
		std::mem::drop(config_guard);

		// -- Add incoming connection
		// dupe
		let incoming_connection = IncomingConnection {
			user: new_user.clone(),
			active_download: None,
			active_download_percent: 0,
			active_download_current_bytes: 0.0,
			is_downloading: false,
			finished_downloads: Vec::new(),
			is_disabled: false,
			//should_reset_connection: false,
			single_connections: Vec::new(),
		};
		let incomig_mutex = Arc::new(Mutex::new(incoming_connection));
		let mut incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		incoming_connections_guard.insert(display_name.clone(), incomig_mutex);
		std::mem::drop(incoming_connections_guard);
		
		// -- Add outgoing connection
		// dupe
		let outgoing_connection = OutgoingConnection::new(new_user.clone(), self.outgoing_connection_manager.is_all_paused);
		let outgoing_connection_arc = Arc::new(Mutex::new(outgoing_connection));
		let outgoing_connection_arc_clone = Arc::clone(&outgoing_connection_arc);
		let outgoing_connection_arc_clone2 = Arc::clone(&outgoing_connection_arc);
		self.outgoing_connection_manager.outgoing_connections.insert(new_user.display_name.clone(), outgoing_connection_arc_clone2);
		
		let local_key_data_arc = Arc::clone(&self.local_key_data);

		let thread_name = display_name.clone();
		thread::spawn(move || {
			handle_outgoing_forever(&outgoing_connection_arc_clone, local_key_data_arc);
			println!("Outgoing final exit {}", thread_name);
		});
		
	}

	fn refresh_shared_with_me(&self) -> Value {
		let mut users_string = String::new();

		let config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		for remote_user in config_guard.trusted_users_public_ids.iter() {
			users_string.push_str("<div><div>");
			let result = panic::catch_unwind(|| self._refresh_single_user(&remote_user)).ok();
			match result {
				Some(value) => {
					users_string.push_str(&value);
				}
				None => {
					// TODO don't duplicate the user header. remove from _refresh_single_user and have this function do it
					users_string.push_str(&format!(
						"<h2>{}</h2>User is online, but an error occurred in connection.",
						remote_user.display_name
					));
				}
			}
			users_string.push_str("</div></div><br>")
		}
		std::mem::drop(config_guard);
		Value::from(format!("{}", users_string))
	}

	fn _refresh_single_user(&self, remote_user: &TrustedUser) -> String {
		let mut ui_string: String = String::new();
		ui_string.push_str(&format!("<h2>{}</h2>", remote_user.display_name));

		let mut remote_addr = String::from(&remote_user.ip_address);
		remote_addr.push_str(":");
		remote_addr.push_str(&remote_user.port);
		let remote_socket_addr: SocketAddr = remote_addr.parse().unwrap();
		let stream =
			TcpStream::connect_timeout(&remote_socket_addr, time::Duration::from_millis(1000));
		let stream = match &stream {
			Ok(s) => s,
			Err(err) => {
				ui_string.push_str(&format!(
					"Cannot Connect. User is probably offline. Verify user's IP address and port are correct.\n{:?}",
					err
				));
				return ui_string;
			}
		};

		let local_key_data_guard = self.local_key_data
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let local_key_pair_bytes = local_key_data_guard.local_key_pair_bytes.clone();
		std::mem::drop(local_key_data_guard);

		let local_key_pair = signature::Ed25519KeyPair::from_pkcs8(local_key_pair_bytes.as_ref()).unwrap();

		let cipher = get_local_to_outgoing_secure_stream_cipher(
			&stream,
			&local_key_pair,
			remote_user.public_id.clone(),
		);
		let mut secure_stream: SecureStream = SecureStream::new(&stream, cipher);
		let shared_file = request_file_list(&mut secure_stream, &remote_user.display_name);
		secure_stream
			.tcp_stream
			.shutdown(Shutdown::Both)
			.expect("shutdown call failed");

		user_files_checkboxes(
			&shared_file,
			&"".to_string(),
			&mut ui_string,
			&remote_user.display_name,
		);

		let mut conn = self
			.outgoing_connection_manager
			.outgoing_connections
			.get(&remote_user.display_name)
			.unwrap()
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		conn.root_file = Some(shared_file);
		std::mem::drop(conn);

		return ui_string;
	}

	fn get_users(&self) -> Value {
		let mut users_string = String::new();
		let config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		for user in config_guard.trusted_users_public_ids.iter() {
			users_string.push_str(&format!(
				"<div><div><h2>{}</h2>Click Refresh<br></div></div><br>",
				&user.display_name.clone()
			));
		}
		std::mem::drop(config_guard);
		Value::from(format!("{}", users_string))
	}





	fn get_my_shared_files(&self) -> Value {
		let mut html = String::new();
		let config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let mut display_names: Vec<String> = Vec::new();
		for user in config_guard.trusted_users_public_ids.iter() {
			display_names.push(user.display_name.to_string());
		}
		for file in config_guard.shared_files.iter() {
			html.push_str("<div>");
			html.push_str(&format!("<div style=\"padding-bottom: 5dip;\"><strong>{}</strong></div>", &file.path));
			html.push_str("<br>Add User: ");
			html.push_str(&format!("<select class=\"option-add-user\" data-file-path=\"{}\"><option></option>", file.path));
			for name in display_names.iter() {
				html.push_str(&format!("<option>{}</option>", name));
			}
			html.push_str("</select>");

			
			html.push_str("<br><br>Shared With:<br>");
			for user in file.shared_with.iter() {
				html.push_str(&format!("&nbsp;&nbsp;&nbsp;&nbsp;{0} <button class=\"remove-shared-with\" data-display-name=\"{0}\" data-file-path=\"{1}\">Remove</button><br><br>", user, file.path));
			}
			html.push_str(&format!("<br><button class=\"remove-file\" data-file-path=\"{}\">Remove from Sharing</button>", file.path));

			html.push_str("</div>");
			html.push_str("<br><hr><br>");
		}
		std::mem::drop(config_guard);
		Value::from(html)
	}

	fn open_downloads(&self) {
		Command::new("explorer.exe").arg(config::get_path_downloads_dir()).spawn();
	}

	fn open_a_download(&self, file_path: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");
		println!("Open a download {}", file_path);
		let p = Path::new(&file_path);
		let dir_path = p.parent().unwrap();
		Command::new("explorer.exe").arg(dir_path).spawn();
	}

	fn get_my_downloads(&self) -> Value {
		let mut download_string = String::new();
		for (owner, connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			
			let is_all_paused = self.outgoing_connection_manager.is_all_paused;
			let is_online = conn.is_online;
			let is_paused = conn.is_paused;
			let offline_str = "User is currently offline";
			if let Some(shared_file) = conn.active_download.clone() {
				let download_percent = conn.active_download_percent.to_string();
				let msg: &str;
				let mut pause_resume = String::from(&format!("<button class=\"pause-download\" data-display-name=\"{0}\">Pause Downloads from {0}</button>", &owner));
				let mut background_color = String::from("rgb(252, 247, 154)");  // YELLOW
				if is_all_paused {
					msg = "All Downloads are Paused";
					pause_resume = String::from("<button disabled>All Downloads are Paused</button>");
				}
				else if is_paused {
					msg = "Paused";
					pause_resume = String::from(&format!("<button class=\"resume-download\" data-display-name=\"{0}\">Resume Downloads from {0}</button>", &owner));
				} 
				else if is_online {
					msg = "Downloading Now...";
					background_color = String::from("rgb(154, 234, 252)");  // BLUE
				}
				else {
					msg = offline_str;
				}
				download_string.push_str(&format!(
					"<download>
				{0} | {1}% | {2}
				<br><br>
				{3}
				<br><br>
				<button class=\"cancel-download\" data-display-name=\"{0}\" data-file-path=\"{3}\">Cancel</button>
				{4}
				</download>
				<br><br>
				<hr>
				<br>
				",
					&owner, &download_percent, msg, &shared_file.path, pause_resume
				));

			}
			std::mem::drop(conn);
		}
		for (owner, connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			let is_online = conn.is_online;
			let offline_str = "User is currently offline";
			for shared_file in conn.download_queue.iter() {
				// If active download is still in the queue, don't duplicate it in the queue list
				if let Some(s) = conn.active_download.clone() {
					if shared_file.replace("\\\\", "\\") == s.clone().path {
						continue;
					}
				}

				let msg: &str;
				if is_online {
					msg = "In Download Queue";
				} else {
					msg = offline_str;
				}
				download_string.push_str(&format!(
					"<download>
				{0} | {1}
				<br><br>
				{2}
				<br><br>
				<button class=\"cancel-download\" data-display-name=\"{0}\" data-file-path=\"{2}\">Cancel</button>
			  </download>
			  <br><br>
			  <hr>
			  <br>
			  ",
					&owner,
					msg,
					&shared_file.replace("\\\\", "\\")
				));
			}
			std::mem::drop(conn);
		}
		for (owner, connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			for (file, destination_path) in conn.finished_downloads.iter() {
				download_string.push_str(&format!(
					"<download>
				{0} | Finished
				<br><br>
				{1}
				<br><br>
				<button class=\"open-a-download\" data-file-path=\"{2}\">Open Download</button>
			  </download>

			  <br><br>
			  <hr>
			  <br>
			  ",
					&owner,
					&file.replace("\\\\", "\\"),
					&destination_path.replace("/", "\\"),
				));
			}
			std::mem::drop(conn);
		}
		for (owner, connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			for file in conn.invalid_downloads.iter() {
				download_string.push_str(&format!(
					"<download>
				{} | Invalid. No longer shared with you.
				<br><br>
				{}
			  </download>
			  <br><br>
			  <hr>
			  <br>
			  ",
					&owner,
					&file.replace("\\\\", "\\")
				));
			}
			std::mem::drop(conn);
		}
		Value::from(download_string)
	}





	fn get_name(&self) -> Value {
		Value::from(NAME)
	}

	fn get_version(&self) -> Value {
		Value::from(VERSION)
	}

	fn get_icon(&self) -> Value {
		let bytes = include_bytes!("window_icon.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_icon_nav_downloads(&self) -> Value {
		let bytes = include_bytes!("ic_fluent_arrow_download_48_regular.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_icon_nav_shared_with_me(&self) -> Value {
		let bytes = include_bytes!("ic_fluent_globe_32_regular.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_icon_nav_my_sharing(&self) -> Value {
		let bytes = include_bytes!("ic_fluent_folder_48_regular.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_icon_nav_users(&self) -> Value {
		let bytes = include_bytes!("ic_fluent_people_32_regular.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_icon_nav_my_id(&self) -> Value {
		let bytes = include_bytes!("ic_fluent_guest_28_regular.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_icon_nav_about(&self) -> Value {
		let bytes = include_bytes!("ic_fluent_info_28_regular.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_page_about(&self) -> Value {
		let page_bytes = include_bytes!("about.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_downloads(&self) -> Value {
		let page_bytes = include_bytes!("downloads.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_my_sharing(&self) -> Value {
		let page_bytes = include_bytes!("my_sharing.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_shared_with_me(&self) -> Value {
		let page_bytes = include_bytes!("shared_with_me.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_welcome(&self) -> Value {
		let page_bytes = include_bytes!("welcome.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_my_id(&self) -> Value {
		let page_bytes = include_bytes!("my_id.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_users(&self) -> Value {
		let page_bytes = include_bytes!("users.htm");
		let page_str = finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn create_new_id(&mut self) -> Value {
		let (private_id_bytes, public_id_bytes) = crypto_ids::generate_id_pair();

		let private_id_string = base64::encode(&private_id_bytes);
		let public_id_string = base64::encode(&public_id_bytes);

		let mut config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		config_guard.my_private_id = private_id_string;

		let mut local_key_data_guard = self.local_key_data
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		local_key_data_guard.local_key_pair = signature::Ed25519KeyPair::from_pkcs8(private_id_bytes.as_ref()).unwrap();
		local_key_data_guard.local_key_pair_bytes = private_id_bytes;
		std::mem::drop(local_key_data_guard);

		config::write_config(&config_guard);
		std::mem::drop(config_guard);
		
		let mut incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for (display_name, incoming_connection) in incoming_connections_guard.iter_mut() {
			let mut connection_guard = incoming_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
			connection_guard = reset_all_connections(connection_guard);
			std::mem::drop(connection_guard);
		}
		std::mem::drop(incoming_connections_guard);

		for (display_name, outgoing_connection) in self.outgoing_connection_manager.outgoing_connections.iter_mut() {
			let mut outgoing_connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
			outgoing_connection_guard.should_reset_connection = true;
			std::mem::drop(outgoing_connection_guard);
		}
	
		return self.get_msg_box_response(0, &format!("New ID created. Your new Public ID is: {}", public_id_string));
	}

	fn get_port(&self) -> Value {
		let config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let port = config_guard.server_port.clone();
		std::mem::drop(config_guard);
		Value::from(port)
	}

	fn get_local_ip(&self) -> Value {
		// TODO
		Value::from("192.168.X.X")
	}

	fn get_sharing_mode(&self) -> Value {
		let sharing_guard = self.sharing_mode	
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let sharing_mode = sharing_guard.clone();
		std::mem::drop(sharing_guard);
		Value::from(sharing_mode.clone())
	}

	fn get_public_id(&self) -> Value {

		let local_key_data_guard = self.local_key_data
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		let public_id = local_key_data_guard.local_key_pair.public_key().as_ref();
		let s = crypto_ids::get_base64_str_from_bytes(public_id.to_vec());
		std::mem::drop(local_key_data_guard);
		Value::from(s)
	}

	fn get_is_first_start(&self) -> Value {
		Value::from(self.is_first_start)
	}

	fn get_current_users(&self) -> Value {
		let mut html = String::new();
		let config_guard = self.config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for user in config_guard.trusted_users_public_ids.iter() {
			
			let enable_button: String;
			let disable_button: String;
			let status: String;
			if user.enabled == true {
				status = "Allowed".to_string();
				disable_button = format!("<button style=\"display: inline-block;\" data-display-name=\"{}\" class=\"disable-user\">Block</button> ", user.display_name);
				enable_button = format!("<button style=\"display: none;\" data-display-name=\"{}\" class=\"enable-user\">Allow</button>", user.display_name);
			} else {
				status = "Blocked".to_string();
				disable_button = format!("<button style=\"display: none;\" data-display-name=\"{}\" class=\"disable-user\">Block</button>", user.display_name);
				enable_button = format!("<button style=\"display: inline-block;\" data-display-name=\"{}\" class=\"enable-user\">Allow</button> ", user.display_name);
			}

			let mut template = String::from(format!("<h3>{}</h3>", user.display_name));
			template.push_str(&format!("Nickname: <span data-display-name=\"{display_name}\" class=\"user-display-name\">{display_name}</span>", display_name=user.display_name));
			template.push_str("<br>");
			template.push_str(&format!("Public ID: <span data-display-name=\"{display_name}\" class=\"user-public-id\">{public_id}</span><input data-display-name=\"{display_name}\" class=\"user-public-id-box\" style=\"display: none;\" type=\"text\" value=\"{public_id}\">", display_name=user.display_name, public_id=user.public_id));
			template.push_str("<br>");
			template.push_str(&format!("IP: <span data-display-name=\"{display_name}\" class=\"user-ip\">{ip}</span><input data-display-name=\"{display_name}\" class=\"user-ip-box\" style=\"display: none;\" type=\"text\" value=\"{ip}\">", display_name=user.display_name, ip=user.ip_address));
			template.push_str("<br>");
			template.push_str(&format!("Port: <span data-display-name=\"{display_name}\" class=\"user-port\">{port}</span><input data-display-name=\"{display_name}\" class=\"user-port-box\" style=\"display: none;\" type=\"text\" value=\"{port}\">", display_name=user.display_name, port=user.port));
			template.push_str("<br>");
			template.push_str(&format!("Status: <span data-display-name=\"{display_name}\" class=\"user-status\">{status}</span>", display_name=user.display_name, status=status));
			template.push_str("<br><br>");
			template.push_str(&format!("<button data-display-name=\"{display_name}\" class=\"edit-user\">Edit</button> ", display_name=user.display_name));
			template.push_str(&format!("<button data-display-name=\"{display_name}\" class=\"apply-user\" style=\"display: none;\">Apply</button> ", display_name=user.display_name));
			template.push_str(&enable_button);
			template.push_str(&disable_button);
			template.push_str(&format!("<button data-display-name=\"{display_name}\" class=\"remove-user\">Remove</button>", display_name=user.display_name));
			template.push_str("<br><br><hr>");
			html.push_str(&template);
		}
		std::mem::drop(config_guard);
		Value::from(html)
	}

	fn get_downloading_from_me(&self) -> Value {
		let mut download_string = String::new();

		let incoming_connections_guard = self.incoming_connections
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		for (user_name, connection) in incoming_connections_guard.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());

			if conn.is_downloading {
				download_string.push_str(&format!(
					"<download>
				{} | {}% | In Progress
				<br>
				{}
			  </download>
			  <hr>
			  ",
					&user_name,
					&conn.active_download_percent,
					&conn.active_download.clone().unwrap().path
				));
			}
			std::mem::drop(conn);
		}

		for (user_name, connection) in incoming_connections_guard.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());

			for path in conn.finished_downloads.iter() {
				download_string.push_str(&format!(
					"<download>
				{} | Finished
				<br>
				{}
			  </download>
			  <hr>
			  ",
					&user_name, path
				));
			}
			std::mem::drop(conn);
		}
		std::mem::drop(incoming_connections_guard);
		Value::from(download_string)
	}

	fn client_start_sharing(&mut self) {
		println!("Starting Client Server for sharing");

		let config_clone = Arc::clone(&self.config);
		let local_key_data_clone = Arc::clone(&self.local_key_data);
		let incoming_clone = Arc::clone(&self.incoming_connections);
		let sharing_clone = Arc::clone(&self.sharing_mode);
		thread::spawn(move || {
			client_wait_for_incoming(
				incoming_clone,
				config_clone,
				local_key_data_clone,
				sharing_clone,
			);
		});

	}
}

fn client_wait_for_incoming(
	incoming_connections: Arc<Mutex<HashMap<String, Arc<Mutex<IncomingConnection>>>>>,
	config: Arc<Mutex<Config>>,
	local_key_data: Arc<Mutex<LocalKeyData>>,
	sharing_mode_arc: Arc<Mutex<String>>,
) {

	println!("Client wait for incoming");

	loop {



		let sharing_guard = sharing_mode_arc	
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		let sharing_mode = sharing_guard.clone();

		std::mem::drop(sharing_guard);

		

		

		if sharing_mode == "Off" {
			thread::sleep(time::Duration::from_secs(1));
			continue;
		}

		let config_guard = config			
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		let mut ip_address = String::new();

		


		if sharing_mode == "Local Network" {
			ip_address.push_str("127.0.0.1");
		} else if sharing_mode == "Internet" {
			ip_address.push_str("0.0.0.0");
		} else {
			std::mem::drop(config_guard);
			panic!(
				"Server flag invalid. 'Local Network' or 'Internet' is valid. Yours -> {}",
				sharing_mode
			);
		}
		ip_address.push_str(":");
		ip_address.push_str(&config_guard.server_port);
		println!(
			"\nWaiting for clients on: {}",
			sharing_mode
		);

		std::mem::drop(config_guard);

		println!("Server waiting for incoming connections...");
		println!("{}", ip_address);
		let listener = TcpListener::bind(ip_address).unwrap();
		listener.set_nonblocking(true).expect("Cannot set non-blocking");


		for stream in listener.incoming() {

			match stream {
				Ok(s) => {
					let sharing_guard = sharing_mode_arc	
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
			
					let new_sharing_mode = sharing_guard.clone();
			
					std::mem::drop(sharing_guard);

					if new_sharing_mode == "Off" || new_sharing_mode != sharing_mode {
						s.shutdown(Shutdown::Both).expect("shutdown call failed");
						break;
					}

					s.set_nonblocking(false).unwrap();

					let config_clone = Arc::clone(&config);
					let local_key_data_guard = local_key_data
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
					let local_key_pair_bytes_clone = local_key_data_guard.local_key_pair_bytes.clone();
					std::mem::drop(local_key_data_guard);
			
					let incoming_clone = Arc::clone(&incoming_connections);
					thread::spawn(move || {
						let client_connecting_ip = s.peer_addr().unwrap().ip().to_string();
						println!("Client connecting: {}", client_connecting_ip);
						let _ = panic::catch_unwind(|| {
							client_handle_incoming(
								incoming_clone,
								&s,
								config_clone,
								local_key_pair_bytes_clone,
							);
						});
						s
							.shutdown(Shutdown::Both)
							.expect("shutdown call failed");
						println!("Connection ended: {}", client_connecting_ip);
					});
				}
				Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
					let sharing_guard = sharing_mode_arc	
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
			
					let new_sharing_mode = sharing_guard.clone();
			
					std::mem::drop(sharing_guard);

					if new_sharing_mode == "Off" || new_sharing_mode != sharing_mode {
						break;
					}
					thread::sleep(time::Duration::from_secs(1));

				}
				Err(e) => {
					println!("ERROR: Failed initial client connection");
					println!("{:?}", e);
					continue;
				}
			}
			
		}
		std::mem::drop(listener);
	}

}


fn client_handle_incoming(
	incoming_connections: Arc<Mutex<HashMap<String, Arc<Mutex<IncomingConnection>>>>>,
	mut stream: &TcpStream,
	config: Arc<Mutex<Config>>,
	local_key_pair_bytes: Vec<u8>,
) {
	let client_connecting_addr = stream.peer_addr().unwrap();
	let client_connecting_ip = client_connecting_addr.ip().to_string();

	// Find client config
	let mut client_config: Option<&TrustedUser> = None;
	let config_guard = config			
	.lock()
	.unwrap_or_else(|poisoned| poisoned.into_inner());
	for client in config_guard.trusted_users_public_ids.iter() {
		if client.ip_address == client_connecting_ip {
			client_config = Some(client);
		}
	}

	let client_config = match client_config {
		Some(found) => Some(found),
		None => {
			println!("!!!! WARNING: Rejected unknown IP: {}", client_connecting_ip);
			stream
				.shutdown(Shutdown::Both)
				.expect("shutdown call failed");
			println!("\tConnection has been shutdown");
			return;
		}
	};

	let remote_config = client_config.unwrap();

	let current_incoming_ip = client_connecting_ip.clone();
	let current_incoming_public_id = remote_config.public_id.clone();

	// Check if disabled
	let incoming_connections_guard = incoming_connections
	.lock()
	.unwrap_or_else(|poisoned| poisoned.into_inner());

	let incoming_connection = incoming_connections_guard
	.get(&remote_config.display_name)
	.unwrap();

	let mut connection_guard = incoming_connection
	.lock()
	.unwrap_or_else(|poisoned| poisoned.into_inner());
	let is_disabled = connection_guard.is_disabled;
	let single_connection = SingleConnection {
		should_reset: false,
	};
	let single_connection_arc = Arc::new(Mutex::new(single_connection));
	let single_connection_arc_clone = Arc::clone(&single_connection_arc);
	connection_guard.single_connections.push(single_connection_arc_clone);
	std::mem::drop(connection_guard);
	std::mem::drop(incoming_connections_guard);
	if is_disabled == true {
		std::mem::drop(config_guard);
		println!("!!!! WARNING: Disabled user connecting. Rejected.: {}", client_connecting_ip);
		stream
			.shutdown(Shutdown::Both)
			.expect("shutdown call failed");
		println!("\tConnection has been shutdown");
		return;
	}

	println!("Connected: {}", remote_config.display_name);
	let local_key_pair =
		signature::Ed25519KeyPair::from_pkcs8(local_key_pair_bytes.as_ref()).unwrap();
	let local_diffie_secret = EphemeralSecret::new(OsRng);
	let local_diffie_public = PublicKey::from(&local_diffie_secret);
	let local_diffie_public_bytes: &[u8; 32] = local_diffie_public.as_bytes();
	let local_diffie_signature_public_bytes = local_key_pair.sign(local_diffie_public_bytes);
	let local_diffie_signed_public_bytes = local_diffie_signature_public_bytes.as_ref();
	// Wait for remote diffie public key
	let mut buffer = [0; TOTAL_BUFFER_SIZE];
	stream.read_exact(&mut buffer).unwrap();
	let mut remote_diffie_public_bytes: [u8; 32] = [0; 32];
	remote_diffie_public_bytes.copy_from_slice(&buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 32]);

	let mut remote_diffie_signed_public_bytes: [u8; 64] = [0; 64];
	remote_diffie_signed_public_bytes
		.copy_from_slice(&buffer[PAYLOAD_OFFSET + 32..PAYLOAD_OFFSET + 32 + 64]);

	let remote_public_key_bytes = crypto_ids::get_bytes_from_base64_str(&remote_config.public_id);
	let remote_public_key =
		signature::UnparsedPublicKey::new(&signature::ED25519, remote_public_key_bytes);
	match remote_public_key.verify(
		&remote_diffie_public_bytes,
		&remote_diffie_signed_public_bytes,
	) {
		Err(_) => {
			panic!(
				"ERROR: Incoming connection failed signature. Public key isn't valid. {} - {}",
				remote_config.display_name, client_connecting_ip
			);
		}
		_ => {}
	}

	// Send remote the local's diffie public key
	let mut diffie_payload: Vec<u8> = Vec::with_capacity(32 + 64); // diffie public key + signature
	for byte in local_diffie_public_bytes {
		diffie_payload.push(byte.clone());
	}

	for byte in local_diffie_signed_public_bytes {
		diffie_payload.push(byte.clone());
	}
	set_buffer(&mut buffer, MSG_SERVER_DIFFIE_PUBLIC, &diffie_payload);
	stream.write_all(&mut buffer).unwrap();
	stream.flush().unwrap();

	// Create encryption key
	let remote_diffie_public_key = PublicKey::from(remote_diffie_public_bytes);
	let local_shared_secret = local_diffie_secret.diffie_hellman(&remote_diffie_public_key);
	let encryption_key = local_shared_secret.as_bytes();
	let key = GenericArray::from_slice(&encryption_key[..]);
	// Create AES and stream
	let cipher = Aes256Gcm::new(key);
	let mut secure_stream: SecureStream = SecureStream::new(stream, cipher);

	// Get list of files shared with user
	let everything_file = get_everything_file(&config_guard, &remote_config.display_name);
	let everything_file_json: String = serde_json::to_string(&everything_file).unwrap();
	let everything_file_json_bytes = everything_file_json.as_bytes().to_vec();

	// IncomingConnection
	let incoming_connections_guard = incoming_connections
	.lock()
	.unwrap_or_else(|poisoned| poisoned.into_inner());

	let incoming_connection = incoming_connections_guard
	.get(&remote_config.display_name)
	.unwrap();

	let incoming_connection_clone = Arc::clone(&incoming_connection);

	// TODO should this be dropped earlier? When is this needed?
	std::mem::drop(incoming_connections_guard);
	std::mem::drop(config_guard);


	loop {
		let mut connection_guard = incoming_connection_clone
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());

		// Check if IP or Public ID has changed
		let has_public_id_changed = connection_guard.user.public_id != current_incoming_public_id;
		let has_ip_changed = connection_guard.user.ip_address != current_incoming_ip;
		if has_ip_changed {
			println!("Incoming conn. IP changed for {}. {} -> {}", connection_guard.user.display_name, current_incoming_ip, connection_guard.user.ip_address);
		}
		if has_public_id_changed {
			println!("Incoming conn. Public ID changed for {}. {} -> {}", connection_guard.user.display_name, current_incoming_public_id, connection_guard.user.public_id);
		}
		let should_reset_connection = single_connection_arc.lock().unwrap().should_reset;
		let should_stop = connection_guard.is_disabled || has_public_id_changed || has_ip_changed || should_reset_connection;
		if should_stop == true {
			connection_guard.is_downloading = false;
			println!("Incoming conn stopped. {}", connection_guard.user.display_name);
		}
		if should_reset_connection {
			println!("Incoming conn reset. {}", connection_guard.user.display_name);
		}
		std::mem::drop(connection_guard);

		if should_stop == true {
			break;
		}

		client_handle_incoming_loop(
			&incoming_connection_clone,
			&single_connection_arc,
			&mut secure_stream,
			&everything_file_json_bytes,
			&everything_file,
		);
	}
}

fn client_handle_incoming_loop(
	incoming_connection: &Arc<Mutex<IncomingConnection>>,
	single_connection_arc: &Arc<Mutex<SingleConnection>>,
	secure_stream: &mut SecureStream,
	everything_file_json_bytes: &Vec<u8>,
	everything_file: &SharedFile,
) {
	println!("Wait for client");

	if single_connection_arc.lock().unwrap().should_reset {
		return;
	}

	secure_stream.read();

	if single_connection_arc.lock().unwrap().should_reset {
		return;
	}

	let client_msg = secure_stream.buffer[0];

	if client_msg == MSG_FILE_LIST {
		println!("Client requests file list");
		if everything_file_json_bytes.len() <= MAX_DATA_SIZE {
			// TODO is this branch not needed?
			secure_stream.write(MSG_FILE_LIST_FINAL, &everything_file_json_bytes);
		} else {
			let mut remaining_bytes = everything_file_json_bytes.len();
			let mut sent_bytes = 0;
			loop {
				if remaining_bytes <= MAX_DATA_SIZE {
					let send_vec = Vec::from(&everything_file_json_bytes[sent_bytes..remaining_bytes+sent_bytes]);
					secure_stream.write(MSG_FILE_LIST_FINAL, &send_vec);
					break;
				} else {
					let send_vec = Vec::from(&everything_file_json_bytes[sent_bytes..MAX_DATA_SIZE+sent_bytes]);
					secure_stream.write(MSG_FILE_LIST_PIECE, &send_vec);
				}
				
				sent_bytes += MAX_DATA_SIZE;
				remaining_bytes -= MAX_DATA_SIZE;
			}
		}
		println!("File list sent");
	} else if client_msg == MSG_FILE_SELECTION_CONTINUE {
		println!("Client sent file selection for downloading");

		// Get client's file selection and optional seek point if continuing download
		let actual_payload_size = get_payload_size_from_buffer(&secure_stream.buffer);
		let mut payload_bytes: Vec<u8> = Vec::with_capacity(actual_payload_size);
		for mut i in 0..actual_payload_size {
			i += PAYLOAD_OFFSET;
			payload_bytes.push(secure_stream.buffer[i]);
		}

		let file_seek_point: u64;
		let client_file_choice: &str;
		let mut seek_bytes: [u8; 8] = [0; 8];
		seek_bytes.copy_from_slice(&payload_bytes[0..8]);
		file_seek_point = u64::from_be_bytes(seek_bytes);
		client_file_choice = str::from_utf8(&payload_bytes[8..]).unwrap();

		println!("    File seek point: {}", file_seek_point);
		println!("    Client chose file {}", client_file_choice);

		// Determine if client's choice is valid
		let client_shared_file = match get_file_by_path(client_file_choice, &everything_file) {
			Some(file) =>  file,
			None => {
				println!("    ! Invalid file choice");				
				secure_stream.write(MSG_FILE_INVALID_FILE, &Vec::with_capacity(1));
				if single_connection_arc.lock().unwrap().should_reset {
					return;
				}
				return;
			}
		};

		// Client cannot select a directory. Client should not allow this to happen.
		if client_shared_file.is_directory {
			println!("    ! Selected directory. Not allowed.");
			secure_stream.write(MSG_CANNOT_SELECT_DIRECTORY, &Vec::with_capacity(1));
			return;
		}

		let mut connection_guard = incoming_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard.is_downloading = true;
		connection_guard.active_download = Some(client_shared_file.clone());
		std::mem::drop(connection_guard);

		// Send file to client
		let mut f = OpenOptions::new()
			.read(true)
			.open(client_file_choice)
			.unwrap();
		f.seek(SeekFrom::Start(file_seek_point)).unwrap();

		println!("Start sending file");

		let mut read_response = 1; // TODO combine with loop?
		let mut read_buffer = [0; MAX_DATA_SIZE];
		let mut current_sent_bytes: usize = file_seek_point as usize;
		let mut download_percent: f64;
		let file_size_f64: f64 = client_shared_file.file_size as f64;
		while read_response != 0 {
			read_response = f.read(&mut read_buffer).unwrap();
			secure_stream.write(MSG_FILE_CHUNK, &read_buffer[0..read_response].to_vec());
			current_sent_bytes += read_response;
			download_percent = ((current_sent_bytes as f64) / file_size_f64) * (100 as f64);
			let mut connection_guard = incoming_connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			connection_guard.active_download_percent = download_percent as usize;
			if single_connection_arc.lock().unwrap().should_reset == true || connection_guard.is_disabled == true {
				std::mem::drop(connection_guard);
				return;
			}
			std::mem::drop(connection_guard);
		}

		// Finished sending file
		println!("Send message finished");
		secure_stream.write(MSG_FILE_FINISHED, &Vec::with_capacity(1));
		println!("File transfer complete");
		let mut connection_guard = incoming_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard.is_downloading = false;
		connection_guard
			.finished_downloads
			.push(client_shared_file.path);
		std::mem::drop(connection_guard);
	} else {
		panic!("Invalid client selection {}", client_msg);
	}
}


impl sciter::EventHandler for Handler {
	dispatch_script_call! {
		fn create_new_id();
		fn set_sharing_mode(Value);
		fn remove_file(Value);
		fn remove_shared_with(Value, Value);
		fn add_files(Value);
		fn add_user_to_file(Value, Value);
		fn download_file_list(Value);
		fn add_new_user(Value, Value, Value, Value);
		fn clear_finished_downloads();
		fn clear_invalid_downloads();
		fn pause_download(Value);
		fn pause_all_downloads();
		fn resume_download(Value);
		fn resume_all_downloads();
		fn cancel_download(Value, Value);
		fn cancel_all_downloads();
		fn remove_user(Value);
		fn disable_user(Value);
		fn enable_user(Value);
		fn edit_user(Value, Value, Value, Value);
		fn open_downloads();
		fn open_a_download(Value);
		fn get_downloading_from_me();
		fn get_icon();
		fn get_icon_nav_downloads();
		fn get_icon_nav_shared_with_me();
		fn get_icon_nav_my_sharing();
		fn get_icon_nav_users();
		fn get_icon_nav_my_id();
		fn get_icon_nav_about();
		fn get_is_first_start();
		fn get_local_ip();
		fn get_my_downloads();
		fn get_my_shared_files();
		fn get_name();
		fn get_page_about();
		fn get_page_downloads();
		fn get_page_my_id();
		fn get_page_my_sharing();
		fn get_page_shared_with_me();
		fn get_page_welcome();
		fn get_page_users();
		fn get_port();
		fn get_public_id();
		fn get_sharing_mode();
		fn get_users();
		fn get_current_users();
		fn get_version();
		fn refresh_shared_with_me();
	}
}



fn main() {
	println!("##########################################");
	println!("# {} v{} #", NAME, VERSION);
	println!("##########################################");
	println!("");

	let args: Vec<String> = env::args().collect();
	println!("CLI args");
	println!("{:?}\n", args);

	println!("Current Working Dir: {:?}", env::current_dir().unwrap());
	println!("Transmitic Path: {:?}", env::current_exe().unwrap());

	create_config_dir();
	let first_load = init_config();
	let config = get_config();
	verify_config(&config);

	// Load local private key pair
	let local_private_key_bytes = crypto_ids::get_bytes_from_base64_str(&config.my_private_id);
	let local_key_pair =
		signature::Ed25519KeyPair::from_pkcs8(local_private_key_bytes.as_ref()).unwrap();
	
	let local_key_data = LocalKeyData {
		local_key_pair: local_key_pair,
		local_key_pair_bytes: local_private_key_bytes,
	};
	let local_key_data_arc = Arc::new(Mutex::new(local_key_data));

	// Incoming Connection
	let mut incoming_connections: HashMap<String, Arc<Mutex<IncomingConnection>>> = HashMap::new();
	for user in config.trusted_users_public_ids.iter() {
		let incoming_connection = IncomingConnection {
			user: user.clone(),
			active_download: None,
			active_download_percent: 0,
			active_download_current_bytes: 0.0,
			is_downloading: false,
			finished_downloads: Vec::new(),
			is_disabled: false,
			//should_reset_connection: false,
			single_connections: Vec::new(),
		};
		let incomig_mutex = Arc::new(Mutex::new(incoming_connection));
		incoming_connections.insert(user.display_name.clone(), incomig_mutex);
	}

	let html = include_bytes!("main.htm");
	let html_final = finalize_htm_page(html);
	let html_bytes = html_final.as_bytes();

	sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
		sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_SYSINFO as u8
			| sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_FILE_IO as u8,
	))
	.unwrap();

	sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();

	let arc_incoming = Arc::new(Mutex::new(incoming_connections));

	let config_arc = Arc::new(Mutex::new(config));
	let config_arc_clone: Arc<Mutex<Config>> = Arc::clone(&config_arc);
	let mut handler = Handler {
		config: config_arc,
		local_key_data: Arc::clone(&local_key_data_arc),
		outgoing_connection_manager: OutgoingConnectionManager::new(
			config_arc_clone,
			Arc::clone(&local_key_data_arc),
			false,
		),
		incoming_connections:arc_incoming,
		is_first_start: first_load,
		sharing_mode: Arc::new(Mutex::new(String::from("Off"))),
	};
	handler.client_start_sharing();

	let mut frame = sciter::Window::new();
	//frame.sciter_handler(DefaultHandler::default());
	frame.event_handler(handler);

	if cfg!(target_os = "macos") {
		frame
			.set_options(sciter::window::Options::DebugMode(true))
			.unwrap();
	}

	// TODO fix
	frame.load_html(html_bytes, Some("example://main.htm"));
	frame.run_app();
}



fn get_payload_size_from_buffer(buffer: &[u8]) -> usize {
	let mut payload_size_bytes = [0; PAYLOAD_SIZE_LEN];
	payload_size_bytes[..].copy_from_slice(&buffer[1..PAYLOAD_SIZE_LEN + 1]);
	let payload_size: usize = u32::from_be_bytes(payload_size_bytes) as usize;
	payload_size
}

fn set_buffer(buffer: &mut [u8], msg_type: u8, payload: &Vec<u8>) {
	buffer[0] = msg_type;

	// Get size of payload
	let payload_size: usize = payload.len();
	let payload_size_u32: u32 = payload_size as u32;
	let payload_size_bytes = payload_size_u32.to_be_bytes();

	// Set size of payload
	buffer[1..PAYLOAD_SIZE_LEN + 1].copy_from_slice(&payload_size_bytes[0..PAYLOAD_SIZE_LEN]);

	// Set payload
	buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload_size].copy_from_slice(&payload);
}

fn request_file_list(secure_stream: &mut SecureStream, client_display_name: &String) -> SharedFile {
	// Request file list
	let mut payload_bytes: Vec<u8> = Vec::new();

	secure_stream.write(MSG_FILE_LIST, &Vec::with_capacity(1));

	// Receive file list
	loop {
		secure_stream.read();
		let server_msg: u8 = secure_stream.buffer[0];
		if server_msg != MSG_FILE_LIST_PIECE && server_msg != MSG_FILE_LIST_FINAL {
			exit_error(format!("Request file list got unexpected MSG: '{:?}'", server_msg));
		}
		let actual_payload_size = get_payload_size_from_buffer(&secure_stream.buffer);
		
		payload_bytes.extend_from_slice(&secure_stream.buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET+actual_payload_size]);
		
		if server_msg == MSG_FILE_LIST_FINAL {
			break;
		}
	}

	// Create FilesJson struct
	let files_str = str::from_utf8(&payload_bytes).unwrap();
	let mut all_files: SharedFile = serde_json::from_str(&files_str).unwrap();
	//println!("{:?}", all_files);

	// Keep valid file names
	remove_invalid_files(&mut all_files, &client_display_name);

	return all_files;
}



fn user_files_checkboxes(
	shared_file: &SharedFile,
	spacer: &String,
	html_str: &mut String,
	files_owner: &String,
) {
	let file_size_string = get_file_size_string(shared_file.file_size);

	let mut ftype = "file";
	if shared_file.is_directory {
		ftype = "dir";
	}

	println!(
		"{}{} | ({}) ({})",
		spacer, shared_file.path, file_size_string, ftype
	);
	let mut html_spacer = String::from("");
	for _ in 0..spacer.len() {
		html_spacer.push_str("&nbsp;");
	}
	let mut check_label = String::from(files_owner);
	check_label.push_str(&shared_file.path);
	let check_str = format!("{0}<checkbox data-owner=\"{4}\">{1}</checkbox> | ({2}) ({3})<br>", html_spacer, shared_file.path, file_size_string, ftype, files_owner);
	html_str.push_str(&check_str);
	if shared_file.is_directory {
		let mut new_spacer = spacer.clone();
		new_spacer.push_str("      ");
		for sub_file in &shared_file.files {
			user_files_checkboxes(&sub_file, &new_spacer, html_str, files_owner);
		}
	}
}
