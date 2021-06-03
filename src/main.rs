use std::env;
use std::panic;
use std::time;
use std::net::{Shutdown, TcpStream, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::str;

extern crate transmitic_core;
use transmitic_core::config;
use transmitic_core::config::TrustedUser;
use transmitic_core::outgoing::{
	get_local_to_outgoing_secure_stream_cipher,
};
use transmitic_core::secure_stream::SecureStream;
use transmitic_core::shared_file::{
	SharedFile,
	FileToDownload,
};
use transmitic_core::transmitic_core::TransmiticCore;
use transmitic_core::utils::{get_file_size_string, request_file_list};

use ring::signature;
use serde::{Deserialize, Serialize};
extern crate sciter;
use sciter::dispatch_script_call;
use sciter::Value;
extern crate x25519_dalek;

const VERSION: &str = "0.3.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic In Development Alpha";

struct Handler {
	transmitic_core: TransmiticCore,
}

#[derive(Serialize, Deserialize, Debug)]
struct FilesJson {
    files: Vec<PathJson>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PathJson {
    path: String,
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

		self.transmitic_core.download_file_list(files_to_download);
	}

	fn set_sharing_mode(&mut self, sharing_mode: Value) -> Value {
		let sharing_mode = self.clean_sciter_string(sharing_mode);

		self.transmitic_core.set_sharing_mode(sharing_mode.clone());

		let msg = format!("Sharing has been set to '{}'", sharing_mode);
		let response = self.get_msg_box_response(0, &msg);
		response
	}


	fn remove_file(&mut self, file_path: Value) -> Value {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");

		self.transmitic_core.remove_file(file_path.clone());

		let msg = format!("'{}' has been removed", file_path);
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn add_files(&mut self, file_paths: Value) -> Value {
		let mut clean_paths = Vec::new();
		for file_path in file_paths.into_iter() {
			let mut file_path = self.clean_sciter_string(file_path);
			file_path = file_path.replace("/", "\\");
			clean_paths.push(file_path);
		}

		let result = self.transmitic_core.add_files(&clean_paths);
		match result {
			Ok(msg) => {
				return self.get_msg_box_response(0, &msg); 
			}
			Err(msg) => {
				return self.get_msg_box_response(1, &msg); 
			}
		}
	}

	fn remove_shared_with(&mut self, display_name: Value, file_path: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");
		let display_name = self.clean_sciter_string(display_name);

		self.transmitic_core.remove_shared_with(&display_name, file_path);
	}

	fn add_user_to_file(&mut self, file_path: Value, display_name: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");
		let display_name = self.clean_sciter_string(display_name);

		self.transmitic_core.add_user_to_file(&display_name, &file_path);
	}

	fn remove_user(&mut self, display_name: Value) {
		let display_name = self.clean_sciter_string(display_name);

		self.transmitic_core.remove_user(&display_name);
	}

	fn disable_user(&mut self, display_name: Value) {
		let display_name = self.clean_sciter_string(display_name);
		
		self.transmitic_core.disable_user(&display_name);
	}

	fn enable_user(&mut self, display_name: Value) {
		let display_name = self.clean_sciter_string(display_name);
		
		self.transmitic_core.enable_user(&display_name);
	}

	fn get_msg_box_response(&self, code: i32, msg: &String) -> Value {
		let mut response = Value::new();
		response.push(Value::from(code));
		response.push(Value::from(msg));
		response
	}

	fn clear_finished_downloads(&mut self) -> Value {
		self.transmitic_core.outgoing_connection_manager.clear_finished_downloads();

		let msg = format!("Finished Downloads have been cleared");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn clear_invalid_downloads(&mut self) -> Value {
		self.transmitic_core.outgoing_connection_manager.clear_invalid_downloads();

		let msg = format!("Invalid Downloads have been cleared");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn pause_download(&mut self, display_name: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);

		self.transmitic_core.outgoing_connection_manager.pause_downloads_for_user(&display_name);

		let msg = format!("Downlods from '{}' will be paused", display_name);
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn pause_all_downloads(&mut self) -> Value {
		self.transmitic_core.outgoing_connection_manager.pause_all_downloads();

		let msg = format!("All downloads will be paused");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn resume_all_downloads(&mut self) -> Value {

		self.transmitic_core.outgoing_connection_manager.resume_all_downloads();

		let msg = format!("All downloads will be resumed");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn resume_download(&mut self, display_name: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);

		self.transmitic_core.outgoing_connection_manager.resume_downloads(&display_name);

		let msg = format!("Downloads from '{}' will be resumed", display_name);
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn cancel_download(&mut self, display_name: Value, file_path: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);
		let file_path = self.clean_sciter_string(file_path);

		self.transmitic_core.outgoing_connection_manager.cancel_single_download(&display_name, &file_path);

		let msg = format!("'{}' will be cancelled", file_path.replace("\\\\", "\\"));
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn cancel_all_downloads(&mut self) -> Value {
		self.transmitic_core.outgoing_connection_manager.cancel_all_downloads();

		let msg = format!("All downloads will be cancelled");
		let response = self.get_msg_box_response(0, &msg);
		response
	}

	fn add_new_user(&mut self, display_name: Value, public_id: Value, ip_address: Value, port: Value) -> Value {
		let display_name = self.clean_sciter_string(display_name);
		let public_id = self.clean_sciter_string(public_id);
		let ip_address = self.clean_sciter_string(ip_address);
		let port = self.clean_sciter_string(port);

		let result = self.transmitic_core.add_new_user(&display_name, &public_id, &ip_address, &port);
		match result {
			Ok(msg) => {
				return  self.get_msg_box_response(0, &msg);
			}
			Err(msg) => {
				return  self.get_msg_box_response(1, &msg);
			}
		}

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

		let result = self.transmitic_core.edit_user(&current_display_name, &new_public_id, &new_ip, &new_port);
		match result {
			Ok(msg) => {
				return  self.get_msg_box_response(0, &msg);
			}
			Err(msg) => {
				return  self.get_msg_box_response(1, &msg);
			}
		}
	}

	fn clean_sciter_string(&self, s: Value) -> String {
		let mut s = s.to_string();
		s = s[1..s.len()-1].to_string();
		s = s.trim().to_string();
		s
	}

	fn refresh_shared_with_me(&self) -> Value {
		let mut users_string = String::new();

		// TODO config_guard
		let config_guard = self.transmitic_core.config			
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
			users_string.push_str("</div></div><br>");
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

		let local_key_data_guard = self.transmitic_core.local_key_data
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

		let mut conn = self.transmitic_core
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
		for user in self.transmitic_core.get_user_names().iter() {
			users_string.push_str(&format!(
				"<div><div><h2>{}</h2>Click Refresh<br></div></div><br>",
				&user
			));
		}
		Value::from(format!("{}", users_string))
	}

	fn get_my_shared_files(&self) -> Value {
		let mut html = String::new();

		let (config_shared_files, all_users) = self.transmitic_core.get_my_shared_files();

		for file in config_shared_files.iter() {
			html.push_str("<div>");
			html.push_str(&format!("<div style=\"padding-bottom: 5dip;\"><strong>{}</strong></div>", &file.path));
			html.push_str("<br>Add User: ");
			html.push_str(&format!("<select class=\"option-add-user\" data-file-path=\"{}\"><option></option>", file.path));
			for name in all_users.iter() {
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
		for (owner, connection) in self.transmitic_core.outgoing_connection_manager.outgoing_connections.iter() {
			let conn = connection
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			
			let is_all_paused = self.transmitic_core.outgoing_connection_manager.is_all_paused;
			let is_online = conn.is_online;
			let is_paused = conn.is_paused;
			let offline_str = "User is currently offline";
			if let Some(shared_file) = conn.active_download.clone() {
				let download_percent = conn.active_download_percent.to_string();
				let msg: &str;
				let mut pause_resume = String::from(&format!("<button class=\"pause-download\" data-display-name=\"{0}\">Pause Downloads from {0}</button>", &owner));
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
		for (owner, connection) in self.transmitic_core.outgoing_connection_manager.outgoing_connections.iter() {
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
		for (owner, connection) in self.transmitic_core.outgoing_connection_manager.outgoing_connections.iter() {
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
		for (owner, connection) in self.transmitic_core.outgoing_connection_manager.outgoing_connections.iter() {
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

	fn get_page_main_bytes(&self) -> Vec<u8> {
		let html = include_bytes!("main.htm");
		let html_final = self.finalize_htm_page(html);
		let html_bytes = html_final.as_bytes().to_vec();
		return html_bytes;
	}

	fn get_page_about(&self) -> Value {
		let page_bytes = include_bytes!("about.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_downloads(&self) -> Value {
		let page_bytes = include_bytes!("downloads.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_my_sharing(&self) -> Value {
		let page_bytes = include_bytes!("my_sharing.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_shared_with_me(&self) -> Value {
		let page_bytes = include_bytes!("shared_with_me.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_welcome(&self) -> Value {
		let page_bytes = include_bytes!("welcome.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_my_id(&self) -> Value {
		let page_bytes = include_bytes!("my_id.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	fn get_page_users(&self) -> Value {
		let page_bytes = include_bytes!("users.htm");
		let page_str = self.finalize_htm_page(page_bytes);
		Value::from(page_str)
	}

	/// This is hack to get around loading CSS on htm pages with sciter
	/// 1. I can't get a relative to path to load css in a frame page
	/// 2. SC_LOAD_DATA works for loading files, but using a frame causes a crash
	/// I don't have any more time to deal with this, so I inject the CSS into the page
	fn inject_css_into_page(&self, page: &str) -> String {
		let bytes = include_bytes!("style.css");
		let css_str = str::from_utf8(bytes).unwrap();
		let new_page = page.replace("/* AUTO CSS INJECTION */", css_str);
		return new_page;
	}

	fn finalize_htm_page(&self, page_bytes: &[u8]) -> String {
		let page_str = str::from_utf8(page_bytes).unwrap();
		let page_str = self.inject_css_into_page(page_str);
		return page_str;
	}

	fn create_new_id(&mut self) -> Value {
		let new_public_id_string = self.transmitic_core.create_new_id();
		return self.get_msg_box_response(0, &format!("New ID created. Your new Public ID is: {}", new_public_id_string));
	}

	fn get_port(&self) -> Value {
		let port = self.transmitic_core.get_port();
		Value::from(port)
	}

	fn get_local_ip(&self) -> Value {
		// TODO
		Value::from("192.168.X.X")
	}

	fn get_sharing_mode(&self) -> Value {
		let sharing_mode = self.transmitic_core.get_sharing_mode();
		Value::from(sharing_mode.clone())
	}

	fn get_public_id(&self) -> Value {
		let s = self.transmitic_core.get_public_id();
		Value::from(s)
	}

	fn get_is_first_start(&self) -> Value {
		Value::from(self.transmitic_core.get_is_first_start())
	}

	fn get_current_users(&self) -> Value {
		let mut html = String::new();

		for user in self.transmitic_core.get_current_users() {
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

		Value::from(html)
	}

	fn get_downloading_from_me(&self) -> Value {
		let mut download_string = String::new();

		let (active_downloading, finished_downloaded) = self.transmitic_core.get_downloading_from_me();

		for active in active_downloading {
			download_string.push_str(&format!(
				"<download>
			{} | {}% | In Progress
			<br>
			{}
		  </download>
		  <hr>
		  ",
				active.display_name,
				active.download_percent,
				active.file_path,
			));
		}

		for finished in finished_downloaded {
			download_string.push_str(&format!(
				"<download>
			{} | Finished
			<br>
			{}
		  </download>
		  <hr>
		  ",
				finished.display_name, finished.file_path
			));
		}

		Value::from(download_string)
	}

	fn client_start_sharing(&mut self) {
		println!("Starting Client Server for sharing");
		self.transmitic_core.client_start_sharing();

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

	sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
		sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_SYSINFO as u8
			| sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_FILE_IO as u8,
	))
	.unwrap();
	sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();

	let transmitic_core = TransmiticCore::new();
	let mut handler = Handler {
		transmitic_core,
	};
	let html_main_bytes = handler.get_page_main_bytes();
	handler.client_start_sharing();

	let mut frame = sciter::Window::new();
	frame.event_handler(handler);

	if cfg!(target_os = "macos") {
		frame
			.set_options(sciter::window::Options::DebugMode(true))
			.unwrap();
	}

	frame.load_html(&html_main_bytes, Some("example://main.htm"));
	frame.run_app();
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
