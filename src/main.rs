use std::env;
use std::panic;
use std::time;
use std::net::{Shutdown, TcpStream, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::str;


use serde::{Deserialize, Serialize};
extern crate sciter;
use sciter::dispatch_script_call;
use sciter::Value;

const VERSION: &str = "0.3.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic In Development Alpha";

struct Handler {
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

	fn get_downloads_in_progress(&self) -> Value {

		let mut response = Value::new();

		let mut item1 = Value::new();
		item1.set_item("owner", "My Mock");
		item1.set_item("percent", "90");
		item1.set_item("path", "C:\\users\\other\\hello.txt");

		let mut item2 = Value::new();
		item2.set_item("owner", "My Mock2");
		item2.set_item("percent", "5");
		item2.set_item("path", "C:\\users\\other\\hello3.txt");

		response.push(item1);
		response.push(item2);

		return response;
	}

	fn get_msg_box_response(&self, code: i32, msg: &String) -> Value {
		let mut response = Value::new();

		response.push(Value::from(code));
		response.push(Value::from(msg));
		response
	}

	fn clean_sciter_string(&self, s: Value) -> String {
		let mut s = s.to_string();
		s = s[1..s.len()-1].to_string();
		s = s.trim().to_string();
		s
	}

	fn fake_click(&self, file_path: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		println!("{}", file_path);
	}

	fn open_a_download(&self, file_path: Value) {
		let mut file_path = self.clean_sciter_string(file_path);
		file_path = file_path.replace("\\\\", "\\");
		println!("Open a download {}", file_path);
		let p = Path::new(&file_path);
		let dir_path = p.parent().unwrap();
		Command::new("explorer.exe").arg(dir_path).spawn();
	}


	fn get_name(&self) -> Value {
		Value::from(NAME)
	}

	fn get_version(&self) -> Value {
		Value::from(VERSION)
	}

	fn get_page_main_bytes(&self) -> Vec<u8> {
		let html = include_bytes!("main.htm");
		//let html_bytes = html_final.as_bytes().to_vec();
		return html.to_vec();
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

	fn get_local_ip(&self) -> Value {
		// TODO
		Value::from("192.168.X.X")
	}

}

impl sciter::EventHandler for Handler {
	dispatch_script_call! {
		fn open_a_download(Value);
		fn fake_click(Value);
		fn get_local_ip();
		fn get_downloads_in_progress();
		fn get_name();
		fn get_page_about();
		fn get_page_downloads();
		fn get_page_my_id();
		fn get_page_my_sharing();
		fn get_page_shared_with_me();
		fn get_page_welcome();
		fn get_page_users();
		fn get_version();
	}
}

fn main() {

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

	let mut handler = Handler {
	};
	let html_main_bytes = handler.get_page_main_bytes();

	let mut frame = sciter::Window::new();
	frame.event_handler(handler);

	if cfg!(target_os = "macos") {
		frame
			.set_options(sciter::window::Options::DebugMode(true))
			.unwrap();
	}

	//frame.load_html(&html_main_bytes, Some("example://app/main.htm"));
	let mut path = env::current_dir().unwrap();
	//path.pop();
	path.push("transmitic\\src\\main.htm");

	let fullp = format!("file://{}", path.to_string_lossy());
	println!("fullp {:?}", fullp);
	frame.load_file(&fullp);
	frame.run_app();
}