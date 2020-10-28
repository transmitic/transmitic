use sciter::dispatch_script_call;
use sciter::Value;

extern crate sciter;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};
use std::collections::VecDeque;
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
use std::{panic, process, thread, time};
use std::{path::PathBuf, sync::Arc};

// CRYPTO
extern crate x25519_dalek;
use aes_gcm::Aes256Gcm;
use aes_gcm::{
	aead::{generic_array::GenericArray, Aead, NewAead},
	aes::Aes256,
	AesGcm,
};

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
const MSG_FILE_CHUNK: u8 = 2;
const MSG_FILE_SELECTION: u8 = 3;
const MSG_FILE_FINISHED: u8 = 4;
const MSG_FILE_INVALID_FILE: u8 = 5;
const MSG_CANNOT_SELECT_DIRECTORY: u8 = 6;
const MSG_FILE_SELECTION_CONTINUE: u8 = 7; // TODO Only use CONTINUE?
const MSG_CLIENT_DIFFIE_PUBLIC: u8 = 8;
const MSG_SERVER_DIFFIE_PUBLIC: u8 = 9;

const MAX_DATA_SIZE: usize = 100_000;
const TOTAL_BUFFER_SIZE: usize = MSG_TYPE_SIZE + PAYLOAD_SIZE_LEN + MAX_DATA_SIZE;
const TOTAL_CRYPTO_BUFFER_SIZE: usize = TOTAL_BUFFER_SIZE + 16;
const PAYLOAD_OFFSET: usize = MSG_TYPE_SIZE + PAYLOAD_SIZE_LEN;

const VERSION: &str = "0.1.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic In Development Alpha";

#[derive(Serialize, Deserialize, Debug)]
struct FilesJson {
	files: Vec<PathJson>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PathJson {
	path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SharedFile {
	path: String,
	is_directory: bool,
	files: Vec<SharedFile>,
	file_size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
	my_private_id_file_name: String,
	trusted_users_public_ids: Vec<TrustedUser>,
	shared_files: Vec<ConfigSharedFile>,
	server_port: String,
	server_visibility: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ConfigSharedFile {
	path: String,
	shared_with: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TrustedUser {
	public_id_file_name: String,
	display_name: String,
	ip_address: String,
	port: String,
}

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

struct FileToDownload {
	file_path: String,
	file_owner: String,
}

struct IncomingConnection {
	user: TrustedUser,
	active_download: Option<SharedFile>,
	active_download_percent: usize,
	active_download_current_bytes: f64,
	is_downloading: bool,
	finished_downloads: Vec<String>,
}

struct OutgoingConnection {
	user: TrustedUser,
	download_queue: VecDeque<String>,
	finished_downloads: Vec<String>,
	invalid_downloads: Vec<String>,
	root_file: Option<SharedFile>,
	active_download: Option<SharedFile>,
	active_download_percent: usize,
	active_download_current_bytes: f64,
	is_online: bool,
}

impl OutgoingConnection {
	pub fn new(user: TrustedUser) -> OutgoingConnection {
		let queue_path = OutgoingConnection::get_path_download_queue(&user);
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
		}
	}

	pub fn get_path_download_queue(user: &TrustedUser) -> PathBuf {
		let mut path = get_path_transmitic_config_dir();
		path.push(format!("download_queue_{}.txt", user.display_name));
		return path;
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
		match &self.active_download {
			Some(shared_file) => {
				write_string.push_str(&shared_file.path);
				write_string.push_str("\n");
			}
			None => {}
		}

		for f in &self.download_queue {
			write_string.push_str(&f);
			write_string.push_str("\n");
		}

		let file_path = OutgoingConnection::get_path_download_queue(&self.user);
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
	remote_addr.push_str(":");
	remote_addr.push_str(&connection_guard.user.port);
	println!(
		"Handle Outgoing {} - {}",
		remote_addr, &connection_guard.user.display_name
	);

	//	move into struct?
	let remote_socket_addr: SocketAddr = remote_addr.parse().unwrap();
	let stream: TcpStream;
	match TcpStream::connect_timeout(&remote_socket_addr, time::Duration::from_millis(1000)) {
		Ok(s) => {
			stream = s;
		}
		Err(e) => {
			println!("Could not connect to '{}': {:?}", remote_addr, e);
			return;
		}
	}
	let remote_public_id_file_name = connection_guard.user.public_id_file_name.clone();
	let cipher = get_local_to_outgoing_secure_stream_cipher(
		&stream,
		&local_key_pair,
		remote_public_id_file_name,
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
				match shared_file {
					None => {
						connection_guard.invalid_downloads.push(file_path);
						connection_guard.download_queue.pop_front();
						connection_guard.write_queue();
						continue;
					}
					_ => {}
				}
				let shared_file = shared_file.unwrap();
				connection_guard.active_download_percent = 0;
				connection_guard.active_download_current_bytes = 0.0;
				connection_guard.active_download = Some(shared_file.clone());
				std::mem::drop(connection_guard);
				client_download_from_remote(
					&mut secure_stream,
					&shared_file,
					remote_user_name,
					outgoing_connection,
				);
				let mut connection_guard = outgoing_connection
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
				connection_guard.active_download = None;
				if shared_file.is_directory {
					connection_guard.finished_downloads.push(shared_file.path);
				}
				connection_guard.download_queue.pop_front();
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
	remote_public_id_file_name: String,
) -> Aes256Gcm {
	let local_diffie_secret = EphemeralSecret::new(&mut OsRng);
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
	let remote_public_key_path = get_path_user_public_id_file(&remote_public_id_file_name);
	let remote_public_key_bytes = fs::read(&remote_public_key_path).unwrap();
	let remote_public_key =
		signature::UnparsedPublicKey::new(&signature::ED25519, remote_public_key_bytes);
	remote_public_key
		.verify(
			&remote_diffie_public_bytes,
			&remote_diffie_signed_public_bytes,
		)
		.unwrap();

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
	remote_user_name: String,
	outgoing_connection: &Arc<Mutex<OutgoingConnection>>,
) {
	let mut root_download_dir = String::from("./downloads/");
	root_download_dir.push_str(&remote_user_name);
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
		match get_file_by_path(file_choice, &a_file) {
			None => {}
			Some(found) => return Some(found.clone()),
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
		new_download_dir.push_str(&'/'.to_string());
		for a_file in &shared_file.files {
			download_shared_file(
				secure_stream,
				a_file,
				&new_download_dir,
				continue_downloading_in_progress,
				outgoing_connection,
				root_download_dir,
			);
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
		if Path::new(&destination_path).exists() {
			let file_length: u64 = metadata(&destination_path).unwrap().len();
			let mut file_continue_payload = file_length.to_be_bytes().to_vec();
			file_continue_payload.extend_from_slice(&shared_file.path.as_bytes());
			selection_msg = MSG_FILE_SELECTION_CONTINUE;
			selection_payload = file_continue_payload;
		} else {
			selection_msg = MSG_FILE_SELECTION;
			selection_payload = shared_file.path.as_bytes().to_vec();
		}
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
		conn.finished_downloads.push(shared_file.path.clone());
		std::mem::drop(conn);
		println!("100%\nDownload finished: {}", destination_path);
	}
}

struct OutgoingConnectionManager {
	config: Config,
	outgoing_connections: HashMap<String, Arc<Mutex<OutgoingConnection>>>,
}

fn handle_outgoing_forever(
	outgoing_connection: &Arc<Mutex<OutgoingConnection>>,
	local_key_pair_bytes: Vec<u8>,
) {
	loop {
		let connection_guard = outgoing_connection
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
		if connection_guard.download_queue.is_empty() {
			std::mem::drop(connection_guard);
			thread::sleep(time::Duration::from_millis(1000));
			continue;
		}
		std::mem::drop(connection_guard);

		let _ = panic::catch_unwind(|| {
			handle_outgoing(outgoing_connection, &local_key_pair_bytes);
		});
		std::mem::drop(outgoing_connection);
		let mut connection_guard = outgoing_connection
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		connection_guard.is_online = false;
		std::mem::drop(connection_guard);
		println!("Error. Reconnecting...");
		thread::sleep(time::Duration::from_millis(10000));
	}
}

impl OutgoingConnectionManager {
	pub fn new(config: Config, local_key_pair_bytes: Vec<u8>) -> OutgoingConnectionManager {
		let mut connections: HashMap<String, Arc<Mutex<OutgoingConnection>>> = HashMap::new();
		for user in config.clone().trusted_users_public_ids {
			let outgoing_connection = OutgoingConnection::new(user.clone());
			let outgoing_connection_arc = Arc::new(Mutex::new(outgoing_connection));
			let outgoing_connection_arc_clone = Arc::clone(&outgoing_connection_arc);
			let outgoing_connection_arc_clone2 = Arc::clone(&outgoing_connection_arc);
			connections.insert(user.display_name.clone(), outgoing_connection_arc_clone2);
			let local_key_pair_bytes_clone = local_key_pair_bytes.clone();
			thread::spawn(move || {
				handle_outgoing_forever(&outgoing_connection_arc_clone, local_key_pair_bytes_clone);
				exit_error("Never hit 001".to_string());
			});
		}

		OutgoingConnectionManager {
			config: config,
			outgoing_connections: connections,
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

struct Handler {
	config: Config,
	local_key_pair: signature::Ed25519KeyPair,
	outgoing_connection_manager: OutgoingConnectionManager,
	local_private_key_bytes: Vec<u8>,
	incoming_connections: Arc<HashMap<String, Arc<Mutex<IncomingConnection>>>>,
	sharing_status: String,
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

	fn refresh_shared_with_me(&self) -> Value {
		let mut users_string = String::new();

		for remote_user in &self.config.trusted_users_public_ids {
			let result = panic::catch_unwind(|| self._refresh_single_user(&remote_user)).ok();
			match result {
				Some(value) => {
					users_string.push_str(&value);
				}
				None => {
					// TODO don't duplicate the user header. remove from _refresh_single_user and have this function do it
					users_string.push_str(&format!("<h2>{}</h2>User is online, but an error occurred in connection.", remote_user.display_name));
				}
			}			
		}
		Value::from(format!("{}", users_string))
	}

	fn _refresh_single_user(&self, remote_user: &TrustedUser) -> String {
		let mut ui_string: String = String::new();
		ui_string.push_str(&format!("<h2>{}</h2><br>", remote_user.display_name));

		let mut remote_addr = String::from(&remote_user.ip_address);
		remote_addr.push_str(":");
		remote_addr.push_str(&remote_user.port);
		let remote_socket_addr: SocketAddr = remote_addr.parse().unwrap();
		let stream = TcpStream::connect_timeout(&remote_socket_addr, time::Duration::from_millis(1000));
		match &stream {
			Ok(s) => {}
			Err(err) => {
				ui_string.push_str(&format!(
					"Cannot Connect. Probably offline. Also verify IP and port are correct.\n{:?}",
					err
				));
				return ui_string;
			}
		}
		let stream = stream.unwrap();

		let remote_public_id_file_name = remote_user.public_id_file_name.clone();
		let cipher = get_local_to_outgoing_secure_stream_cipher(
			&stream,
			&self.local_key_pair,
			remote_public_id_file_name,
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
		println!("ROOT FILE IS: {:?}", conn.root_file);
		std::mem::drop(conn);

		return ui_string;
	}

	fn get_users(&self) -> Value {
		let mut users_string = String::new();
		for user in &self.config.trusted_users_public_ids {
			users_string.push_str(&format!(
				"<h2>{}</h2>Click Refresh<br>",
				&user.display_name.clone()
			));
		}
		Value::from(format!("{}", users_string))
	}

	fn client_start_sharing(&mut self) {
		println!("Starting Client Server for sharing");
		// Start TCP listener
		let mut ip_address = String::new();
		if self.config.server_visibility == "local" {
			ip_address.push_str("127.0.0.1");
		} else if self.config.server_visibility == "internet" {
			ip_address.push_str("0.0.0.0");
		} else {
			panic!(
				"Server flag invalid. 'local' or 'internet' is valid. Yours -> {}",
				&self.config.server_visibility
			);
		}
		ip_address.push_str(":");
		ip_address.push_str(&self.config.server_port);
		println!(
			"\nWaiting for clients on: {}",
			self.config.server_visibility
		);

		let config_clone = self.config.clone();
		let local_key_pair_bytes_clone = self.local_private_key_bytes.clone();
		let incoming_clone = Arc::clone(&self.incoming_connections);
		thread::spawn(move || {
			client_wait_for_incoming(
				incoming_clone,
				ip_address,
				config_clone,
				local_key_pair_bytes_clone,
			);
		});

		self.sharing_status = String::from("Sharing ON. To stop sharing, quit Transmitic.");
	}

	fn get_page_about(&self) -> Value {
		let html = format!(
			"<html>
		<head>
		<style>
			html {{
				behavior: htmlarea;
			}}
		</style>
		</head>
		<body>
			<br>
			<h3>{}</h3>
			<h3>v{}</h3>
			<h3>https://transmitic.io</h3>
		</body>
		</html>
		",
			NAME, VERSION
		);
		Value::from(html)
	}

	fn get_my_shared_files(&self) -> Value {
		let mut html = String::new();
		for file in self.config.shared_files.iter() {
			html.push_str(&file.path);
			html.push_str("<br>Shared With:<br>");
			for user in file.shared_with.iter() {
				html.push_str(&format!("&nbsp;&nbsp;&nbsp;&nbsp;{}<br>", user));
			}
			html.push_str("<br><br>");
		}
		Value::from(html)
	}

	fn get_my_downloads(&self) -> Value {
		let mut download_string = String::new();
		for (owner, connection) in self.outgoing_connection_manager.outgoing_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			let is_online = conn.is_online;
			let offline_str = "User is currently offline";
			match conn.active_download.clone() {
				Some(shared_file) => {
					let download_percent = conn.active_download_percent.to_string();
					let msg: &str;
					if is_online {
						msg = "Downloading Now...";
					} else {
						msg = offline_str;
					}
					download_string.push_str(&format!(
						"<download>
					{} | {}% | {}
					<br>
					{}
				  </download>
				  <br><br>
				  <hr>
				  <br>",
						&owner, &download_percent, msg, &shared_file.path
					));
				}
				None => {}
			}

			for shared_file in conn.download_queue.iter() {
				// If active download is still in the queue, don't duplicate it in the queue list
				match conn.active_download.clone() {
					Some(s) => {
						if shared_file.replace("\\\\", "\\") == s.clone().path {
							continue;
						}
					}
					None => {}
				}

				let msg: &str;
				if is_online {
					msg = "In Download Queue";
				} else {
					msg = offline_str;
				}
				download_string.push_str(&format!(
					"<download>
				{} | {}
				<br>
				{}
			  </download>
			  <br><br>
			  <hr>
			  <br>",
					&owner, msg, &shared_file
				));
			}

			for file in conn.finished_downloads.iter() {
				download_string.push_str(&format!(
					"<download>
				{} | Finished
				<br>
				{}
			  </download>
			  <br><br>
			  <hr>
			  <br>",
					&owner, &file
				));
			}

			for file in conn.invalid_downloads.iter() {
				download_string.push_str(&format!(
					"<download>
				{} | Invalid. No longer shared with you.
				<br>
				{}
			  </download>
			  <br><br>
			  <hr>
			  <br>",
					&owner, &file
				));
			}
			std::mem::drop(conn);
		}
		Value::from(download_string)
	}

	// TODO helper function for all these
	fn get_icon(&self) -> Value {
		let bytes = include_bytes!("window_icon.svg");
		let str = str::from_utf8(bytes).unwrap();
		Value::from(str)
	}

	fn get_page_downloads(&self) -> Value {
		let page_bytes = include_bytes!("downloads.htm");
		let page_str = str::from_utf8(page_bytes).unwrap();
		Value::from(page_str)
	}

	fn get_page_my_sharing(&self) -> Value {
		let page_bytes = include_bytes!("my_sharing.htm");
		let page_str = str::from_utf8(page_bytes).unwrap();
		Value::from(page_str)
	}

	fn get_page_shared_with_me(&self) -> Value {
		let page_bytes = include_bytes!("shared_with_me.htm");
		let page_str = str::from_utf8(page_bytes).unwrap();
		Value::from(page_str)
	}

	fn get_sharing_status(&self) -> Value {
		Value::from(self.sharing_status.clone())
	}

	fn get_downloading_from_me(&self) -> Value {
		let mut download_string = String::new();
		for (user_name, connection) in self.incoming_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			let is_downloading = conn.is_downloading;

			if is_downloading {
				download_string.push_str(&format!(
					"<download>
				{} | {}% | In Progress
				<br>
				{}
			  </download>
			  <br><br>
			  <hr>
			  <br>",
					&user_name,
					&conn.active_download_percent,
					&conn.active_download.clone().unwrap().path
				));
			}
			std::mem::drop(conn);
		}

		for (user_name, connection) in self.incoming_connections.iter() {
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
			  <br><br>
			  <hr>
			  <br>",
					&user_name, path
				));
			}
			std::mem::drop(conn);
		}
		Value::from(download_string)
	}
}

fn client_wait_for_incoming(
	incoming_connections: Arc<HashMap<String, Arc<Mutex<IncomingConnection>>>>,
	ip_address: String,
	config: Config,
	local_key_pair_bytes: Vec<u8>,
) {
	println!("Server waiting for incoming connections...");
	let listener = TcpListener::bind(ip_address).unwrap();
	for stream in listener.incoming() {
		let stream = stream;
		let stream = match stream {
			Ok(s) => s,
			Err(error) => {
				println!("ERROR: Failed initial client connection");
				println!("{:?}", error);
				continue;
			}
		};

		let config_clone = config.clone();
		let local_key_pair_bytes_clone = local_key_pair_bytes.clone();
		let incoming_clone = Arc::clone(&incoming_connections);
		thread::spawn(move || {
			let client_connecting_ip = stream.peer_addr().unwrap().ip().to_string();
			println!("Client connecting: {}", client_connecting_ip);
			let _ = panic::catch_unwind(|| {
				client_handle_incoming(
					incoming_clone,
					&stream,
					config_clone,
					local_key_pair_bytes_clone,
				);
			});
			stream
				.shutdown(Shutdown::Both)
				.expect("shutdown call failed");
			println!("Connection ended: {}", client_connecting_ip);
		});
	}
}

fn client_handle_incoming(
	incoming_connections: Arc<HashMap<String, Arc<Mutex<IncomingConnection>>>>,
	mut stream: &TcpStream,
	config: Config,
	local_key_pair_bytes: Vec<u8>,
) {
	let client_connecting_addr = stream.peer_addr().unwrap();
	let client_connecting_ip = client_connecting_addr.ip().to_string();

	// Find client config
	let mut client_config: Option<&TrustedUser> = None;
	for client in config.trusted_users_public_ids.iter() {
		if client.ip_address == client_connecting_ip {
			client_config = Some(client);
		}
	}

	match client_config {
		Some(found) => client_config = Some(found),
		None => {
			println!("!!!! WARNING: Rejected IP: {}", client_connecting_ip);
			stream
				.shutdown(Shutdown::Both)
				.expect("shutdown call failed");
			println!("\tConnection has been shutdown");
			return;
		}
	}

	let remote_config = client_config.unwrap();

	println!("Connected: {}", remote_config.display_name);
	let local_key_pair =
		signature::Ed25519KeyPair::from_pkcs8(local_key_pair_bytes.as_ref()).unwrap();
	let local_diffie_secret = EphemeralSecret::new(&mut OsRng);
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
	let remote_public_key_path = get_path_user_public_id_file(&remote_config.public_id_file_name);
	println!("**KEY PATH: {:?}", remote_public_key_path);
	let remote_public_key_bytes = fs::read(&remote_public_key_path).unwrap();
	let remote_public_key =
		signature::UnparsedPublicKey::new(&signature::ED25519, remote_public_key_bytes);
	match remote_public_key
		.verify(
			&remote_diffie_public_bytes,
			&remote_diffie_signed_public_bytes,
		) {
			Err(e) => {
				panic!("ERROR: Incoming connection failed signature. Public key isn't valid. {} - {}", remote_config.display_name, client_connecting_ip);
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
	let everything_file = get_everything_file(&config, &remote_config.display_name);
	let everything_file_json: String = serde_json::to_string(&everything_file).unwrap();
	let everything_file_json_bytes = everything_file_json.as_bytes().to_vec();

	// IncomingConnection
	let incoming_connection = incoming_connections
		.get(&remote_config.display_name)
		.unwrap();

	loop {
		client_handle_incoming_loop(
			&incoming_connection,
			&mut secure_stream,
			&everything_file_json_bytes,
			&everything_file,
		);
	}
}

fn client_handle_incoming_loop(
	incoming_connection: &Arc<Mutex<IncomingConnection>>,
	secure_stream: &mut SecureStream,
	everything_file_json_bytes: &Vec<u8>,
	everything_file: &SharedFile,
) {
	println!("Wait for client");

	secure_stream.read();
	let client_msg = secure_stream.buffer[0];

	if client_msg == MSG_FILE_LIST {
		println!("Client requests file list");
		secure_stream.write(MSG_FILE_LIST, &everything_file_json_bytes);
		println!("File list sent");
	} else if client_msg == MSG_FILE_SELECTION || client_msg == MSG_FILE_SELECTION_CONTINUE {
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
		if client_msg == MSG_FILE_SELECTION_CONTINUE {
			let mut seek_bytes: [u8; 8] = [0; 8];
			seek_bytes.copy_from_slice(&payload_bytes[0..8]);
			file_seek_point = u64::from_be_bytes(seek_bytes);
			client_file_choice = str::from_utf8(&payload_bytes[8..]).unwrap();
		} else {
			file_seek_point = 0;
			client_file_choice = str::from_utf8(&payload_bytes).unwrap();
		}
		println!("    File seek point: {}", file_seek_point);
		println!("    Client chose file {}", client_file_choice);

		// Determine if client's choice is valid
		let client_shared_file: SharedFile;
		match get_file_by_path(client_file_choice, &everything_file) {
			Some(file) => client_shared_file = file,
			None => {
				println!("    ! Invalid file choice");
				secure_stream.write(MSG_FILE_INVALID_FILE, &Vec::with_capacity(1));
				return;
			}
		}

		// Client cannot select a directory. Client should not allow this to happen.
		if client_shared_file.is_directory {
			println!("    ! Selected directory");
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

fn get_everything_file(config: &Config, display_name: &String) -> SharedFile {
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

fn process_shared_file(shared_file: &mut SharedFile) {
	if shared_file.is_directory == false {
		return;
	}

	if shared_file.is_directory {
		for file in fs::read_dir(&shared_file.path).unwrap() {
			let file = file.unwrap();
			let path = file.path();
			let path_string = String::from(path.to_str().unwrap());
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

impl sciter::EventHandler for Handler {
	dispatch_script_call! {
		fn refresh_shared_with_me();
		fn get_users();
		fn download_file_list(Value);
		fn get_downloading_from_me();
		fn get_my_downloads();
		fn get_my_shared_files();
		fn client_start_sharing();
		fn get_icon();
		fn get_page_about();
		fn get_page_downloads();
		fn get_page_shared_with_me();
		fn get_page_my_sharing();
		fn get_sharing_status();
	}
}

fn get_size_of_directory(path: &str) -> usize {
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
	if args.len() != 1 {
		if args[1] == "generate-keys" {
			if args.len() != 3 {
				println!("ERROR: You must specify the name of your key as an arg");
				process::exit(1);
			} else {
				println!("Generating Keys");
				generate_keys(args[2].as_str());
				println!("Keys generated");
				process::exit(0);
			}
		} else {
			println!("ERROR: Invalid cli arg: {}", args[1]);
			process::exit(1);
		}
	}
	let config = get_config();
	verify_config(&config);
	let remote_config = config.clone();

	// Load local private key pair
	let mut local_key_pair_path = get_path_my_config_dir();
	local_key_pair_path.push(&config.my_private_id_file_name);
	println!("Local Key Pair Path: {:?}", &local_key_pair_path);
	let local_private_key_bytes = fs::read(local_key_pair_path).unwrap();
	let local_key_pair =
		signature::Ed25519KeyPair::from_pkcs8(local_private_key_bytes.as_ref()).unwrap();

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
		};
		let incomig_mutex = Arc::new(Mutex::new(incoming_connection));
		incoming_connections.insert(user.display_name.clone(), incomig_mutex);
	}

	let html = include_bytes!("main.htm");

	sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
		sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_SYSINFO as u8
			| sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_FILE_IO as u8,
	))
	.unwrap();

	sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();

	let arc_incoming = Arc::new(incoming_connections);
	let handler = Handler {
		config: config,
		local_key_pair: local_key_pair,
		outgoing_connection_manager: OutgoingConnectionManager::new(
			remote_config,
			local_private_key_bytes.clone(),
		),
		local_private_key_bytes: local_private_key_bytes.clone(),
		incoming_connections: arc_incoming,
		sharing_status: String::from("Sharing OFF.")
	};

	let mut frame = sciter::Window::new();
	frame.event_handler(handler);

	if cfg!(target_os = "macos") {
		frame
			.set_options(sciter::window::Options::DebugMode(true))
			.unwrap();
	}
	frame.load_html(html, Some("example://main.htm"));
	frame.run_app();
}

fn get_blocked_file_name_chars() -> String {
	return String::from("(){}\"'$<>#?&;%!");
}

fn get_blocked_display_name_chars() -> String {
	let mut chars = get_blocked_file_name_chars();
	chars.push_str("/\\:[]");
	return chars;
}

fn verify_config(config: &Config) {
	let blocked_file_name_chars = get_blocked_file_name_chars();
	let blocked_extended = get_blocked_display_name_chars();

	// my_private_id_file_name file name is valid
	for c in blocked_extended.chars() {
		if config.my_private_id_file_name.contains(c) == true {
			exit_error(format!("my_private_id_file_name file name from config.json contains char '{}'. The following are not allowed '{}'", c, blocked_extended));
		}
	}

	// my_private_id_file_name exists
	let mut local_key_pair_path = get_path_my_config_dir();
	local_key_pair_path.push(&config.my_private_id_file_name);
	if local_key_pair_path.exists() == false {
		exit_error(format!(
			"my_private_id_file_name file from config.json doesn't exist: '{}'",
			local_key_pair_path.to_str().unwrap()
		));
	}

	// server vis
	let server_vis = &config.server_visibility;
	if server_vis != "local" && server_vis != "internet" {
		exit_error(format!(
			"config.json 'server_visibility' can only be 'local' or 'internet'"
		));
	}

	// public ids file name is valid
	for key in &config.trusted_users_public_ids {
		for c in blocked_extended.chars() {
			if key.public_id_file_name.contains(c) == true {
				exit_error(format!("public id file name '{}' from config.json contains char '{}'. The following are not allowed '{}'", key.public_id_file_name, c, blocked_extended));
			}
		}
	}

	// public ids exist
	for key in &config.trusted_users_public_ids {
		let path = get_path_user_public_id_file(&key.public_id_file_name);
		if path.exists() == false {
			exit_error(format!(
				"Public ID key in config for user '{}' doesn't exist: '{}'",
				key.display_name,
				path.to_str().unwrap()
			));
		}
	}

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

fn get_path_user_public_id_file(file_name: &String) -> PathBuf {
	let mut path = get_path_users_public_ids_dir();
	path.push(file_name);
	return path;
}

fn get_config() -> Config {
	let config_path = get_path_config_json();
	println!("config path: {:?}", config_path);
	if config_path.exists() == false {
		exit_error(format!(
			"config.json does not exist at '{}'",
			config_path.to_str().unwrap()
		));
	}
	let config_string = fs::read_to_string(&config_path).unwrap();
	let config: Config;
	match serde_json::from_str(&config_string.clone()) {
		Ok(c) => {
			config = c;
		}
		Err(e) => {
			println!("{:?}", e);
			exit_error(format!(
				"config.json is invalid '{}'",
				config_path.to_str().unwrap()
			));
		}
	}
	return config;
}

fn exit_error(msg: String) -> ! {
	println!("\n!!!! ERROR: {}", msg);
	println!("Transmitic has stopped");
	process::exit(1);
}

fn create_config_dir() {
	let path = get_path_transmitic_config_dir();
	println!("Transmitic Config Dir: {:?}", path);
	fs::create_dir_all(path).unwrap();

	let path = get_path_my_config_dir();
	fs::create_dir_all(path).unwrap();

	let path = get_path_users_public_ids_dir();
	fs::create_dir_all(path).unwrap();
}

fn get_path_transmitic_config_dir() -> PathBuf {
	let mut path = env::current_dir().unwrap();
	path.push("transmitic_config");
	return path;
}

fn get_path_my_config_dir() -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push("my_config");
	return path;
}

fn get_path_users_public_ids_dir() -> PathBuf {
	let mut path = get_path_transmitic_config_dir();
	path.push("users_public_ids");
	return path;
}

fn get_path_config_json() -> PathBuf {
	let mut path = get_path_my_config_dir();
	path.push("config.json");
	return path;
}

fn generate_keys(name: &str) {
	// Generate a key pair in PKCS#8 (v2) format.
	let rng = rand::SystemRandom::new();
	let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

	let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

	let public_key_bytes = key_pair.public_key().as_ref();

	let mut file_name_private_key = String::from(name);
	file_name_private_key.push_str("_private_id.id");

	let mut file_name_public_key = String::from(name);
	file_name_public_key.push_str("_public_id.id");

	let mut private_key_file = File::create(file_name_private_key).unwrap();
	private_key_file.write(pkcs8_bytes.as_ref()).unwrap();

	let mut public_key_file = File::create(file_name_public_key).unwrap();
	public_key_file.write(public_key_bytes).unwrap();
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
	secure_stream.write(MSG_FILE_LIST, &Vec::with_capacity(1));

	// Receive file list
	secure_stream.read();
	let actual_payload_size = get_payload_size_from_buffer(&secure_stream.buffer);
	let mut payload_bytes: Vec<u8> = Vec::with_capacity(actual_payload_size);
	for mut i in 0..actual_payload_size {
		i += PAYLOAD_OFFSET;
		payload_bytes.push(secure_stream.buffer[i]);
	}

	// Create FilesJson struct
	let files_str = str::from_utf8(&payload_bytes).unwrap();
	let all_files: SharedFile = serde_json::from_str(&files_str).unwrap();
	//println!("{:?}", all_files);

	// Verify file names are valid
	quit_if_invalid_file(&all_files, &client_display_name);

	println!("\n\n#### Available Files & Directories ####");
	print_shared_files(&all_files, &"".to_string());

	return all_files;
}

fn quit_if_invalid_file(shared_file: &SharedFile, client_display_name: &String) {
	let blocked_chars = get_blocked_file_name_chars();
	for c in blocked_chars.chars() {
		if shared_file.path.contains(c) == true {
			exit_error(format!("ALERT: The user '{}' attempted to send you a file with the blocked char '{}'. This might have been a malicious attempt.", client_display_name, c.to_string()));
		}
	}

	if shared_file.is_directory {
		for sub_file in &shared_file.files {
			quit_if_invalid_file(&sub_file, &client_display_name);
		}
	}
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
	let check_str = format!("{}<input type=\"checkbox\" name=\"{4}\" value=\"{1}\" data-owner=\"{5}\"><label for=\"{4}\">{}</label> | ({}) ({})<br>", html_spacer, shared_file.path, file_size_string, ftype, check_label, files_owner);
	html_str.push_str(&check_str);
	if shared_file.is_directory {
		let mut new_spacer = spacer.clone();
		new_spacer.push_str("      ");
		for sub_file in &shared_file.files {
			user_files_checkboxes(&sub_file, &new_spacer, html_str, files_owner);
		}
	}
}

fn print_shared_files(shared_file: &SharedFile, spacer: &String) {
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

fn get_file_size_string(mut bytes: u64) -> String {
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
