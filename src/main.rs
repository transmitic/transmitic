use std::env;
use std::path::Path;
use std::process::Command;
use std::str;


use serde::{Deserialize, Serialize};
extern crate sciter;
use sciter::dispatch_script_call;
use sciter::Value;

const VERSION: &str = "0.10.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic Beta";
const URL: &str = "https://transmitic.io";

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


	fn get_app_display_name(&self) -> Value {
		Value::from(NAME)
	}

	fn get_app_display_version(&self) -> Value {
		Value::from(format!("v{}", VERSION))
	}

    fn get_app_url(&self) -> Value {
        Value::from(URL)
    }

	fn get_local_ip(&self) -> Value {
		// TODO
		Value::from("192.168.X.X")
	}

    fn get_port(&self) -> Value {
        Value::from("PORTHERE")
    }

    fn get_public_id(&self) -> Value {
        Value::from("PUBLICHERE")
    }

}

impl sciter::EventHandler for Handler {
	dispatch_script_call! {
		fn fake_click(Value);

        fn get_app_display_name();
        fn get_app_display_version();
        fn get_app_url();
        
        fn get_downloads_in_progress();
		fn get_local_ip();
        fn get_port();
        fn get_public_id();

        fn open_a_download(Value);
	}
}

fn main() {
    println!("{} v{}", NAME, VERSION);
    println!("{}", URL);
	let args: Vec<String> = env::args().collect();
	println!("cli args");
	println!("{:?}\n", args);

	let mut sciter_path = env::current_dir().unwrap();
    sciter_path.push("transmitic\\src\\main.htm");
    let sciter_string = format!("file://{}", sciter_path.to_string_lossy());

    println!("Current Working Dir: '{:?}'", env::current_dir().unwrap());
	println!("Transmitic Path: '{:?}'", env::current_exe().unwrap());
    println!("Sciter path: '{}'", sciter_string);

	sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
		sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_SYSINFO as u8
			| sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_FILE_IO as u8,
	))
	.unwrap();
	sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();

	let mut handler = Handler {
	};

	let mut frame = sciter::Window::new();
	frame.event_handler(handler);

	if cfg!(target_os = "macos") {
		frame
			.set_options(sciter::window::Options::DebugMode(true))
			.unwrap();
	}

	frame.load_file(&sciter_string);
	frame.run_app();
}