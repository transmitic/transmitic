use std::env;
use std::error::Error;
use std::f64::consts::FRAC_1_PI;
use std::path::Path;
use std::process::Command;
use std::str;

use serde::{Deserialize, Serialize};
extern crate sciter;
use sciter::dispatch_script_call;
use sciter::Value;
use transmitic_core::transmitic_core::TransmiticCore;

const VERSION: &str = "0.10.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic Beta";
const URL: &str = "https://transmitic.io";

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
    fn add_files(&self, files: Value) {}

    fn add_folder(&self, folder: Value) {}

    fn add_new_user(&mut self, new_nickname: Value, new_public_id: Value, new_ip: Value, new_port: Value) -> Value {
        let new_nickname = self.clean_sciter_string(new_nickname);
        let new_public_id = self.clean_sciter_string(new_public_id);
        let new_ip = self.clean_sciter_string(new_ip);
        let new_port = self.clean_sciter_string(new_port);

        println!("{}", new_nickname);
        println!("{}", new_port);

        let response: Value;
        match self.transmitic_core.add_new_user(new_nickname, new_public_id, new_ip, new_port) {
            Ok(_) => response = self.get_msg_box_response(0, &"".to_string()),
            Err(e) => response = self.get_msg_box_response(1, &e.to_string()),
        }
        return response;
    }

    fn add_user_to_shared(&self, nickname: Value, file_path: Value) {
        let nickname = self.clean_sciter_string(nickname);
        let file_path = self.clean_sciter_string(file_path);
    }

    fn create_new_id(&mut self) -> Value {
        let response: Value;
        match self.transmitic_core.create_new_id() {
            Ok(_) => response = self.get_msg_box_response(0, &"".to_string()),
            Err(e) => response = self.get_msg_box_response(1, &e.to_string()),
        }
        return response;
    }

    fn download_selected(&self, files: Value) {}

    fn downloads_open(&self) {}

    fn downloads_clear_finished(&self) {}

    fn downloads_clear_finished_from_me(&self) {}

    fn downloads_cancel_invalid(&self) {}

    fn downloads_cancel_all(&self) {}

    fn downloads_pause_all(&self) {}

    fn downloads_resume_all(&self) {}

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
        s = s[1..s.len() - 1].to_string();
        s = s.trim().to_string();
        s
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

    fn get_my_sharing_state(&self) -> Value{
        let sharing_state = self.transmitic_core.get_my_sharing_state();
        return self.get_msg_box_response(0, &sharing_state);
    }

    fn get_shared_users(&self) -> Value {
        let shared_users = self.transmitic_core.get_shared_users();
        let mut user_list = Value::new();

        for user in shared_users {
            let mut new_user_dict = Value::new();
            // TODO use serde to get the string? 
            //  But the struct may evenutally contain data that the UI doesn't need?
            //  But that would just be ignored, that wouldn't be a problem

            new_user_dict.set_item("nickname", user.nickname);
            new_user_dict.set_item("public_id", user.public_id);
            new_user_dict.set_item("ip", user.ip);
            new_user_dict.set_item("port", user.port);
            if user.allowed {
                new_user_dict.set_item("status", "Allowed");
            } else {
                new_user_dict.set_item("status", "Blocked");
            }
            
            user_list.push(new_user_dict);
            
        }

       return user_list;
    }

    fn get_sharing_port(&self) -> Value {
        let sharing_port = self.transmitic_core.get_sharing_port();
        return self.get_msg_box_response(0, &sharing_port);
    }

    fn get_public_id_string(&self) -> Value {
        let public_id_string = self.transmitic_core.get_public_id_string();
        Value::from(public_id_string)
    }

    fn refresh_shared_with_me(&self) {}

    fn remove_file_from_sharing(&self, file_path: Value) {
        let file_path = self.clean_sciter_string(file_path);
    }

    fn remove_user(&mut self, nickname: Value) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let response;
        match self.transmitic_core.remove_user(nickname) {
            Ok(_) => response = self.get_msg_box_response(0, &"".to_string()),
            Err(e) => response = self.get_msg_box_response(1, &e.to_string()),
        }

        return response;
    }

    fn remove_user_from_sharing(&self, nickname: Value) {
        let nickname = self.clean_sciter_string(nickname);
    }

    fn set_my_sharing_state(&mut self, state: Value) -> Value {
        let state = self.clean_sciter_string(state);
        let response: Value;
        match self.transmitic_core.set_my_sharing_state(state) {
            Ok(_) => response = self.get_msg_box_response(0, &"".to_string()),
            Err(e) => response = self.get_msg_box_response(1, &e.to_string()),
        }

        return response;

    }

    fn set_port(&mut self, port: Value) -> Value {
        let port = self.clean_sciter_string(port);

        let response: Value;
        match self.transmitic_core.set_port(port) {
            Ok(_) => response = self.get_msg_box_response(0, &"".to_string()),
            Err(e) => response = self.get_msg_box_response(1, &e.to_string()),
        }
        
        return response;
    }

    fn set_user_is_allowed_state(&mut self, nickname: Value, is_allowed: Value) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let is_allowed = match is_allowed.to_bool() {
            Some(is_allowed) => is_allowed,
            None => return self.get_msg_box_response(1, &"is_allowed is not a bool".to_string()),
        };

        let response: Value;
        match self.transmitic_core.set_user_is_allowed_state(nickname, is_allowed) {
            Ok(_) => response = self.get_msg_box_response(0, &"".to_string()),
            Err(e) => response = self.get_msg_box_response(1, &e.to_string()),
        }
        
        return response;
    }

    fn update_user(
        &self,
        new_nickname: Value,
        new_public_id: Value,
        new_ip: Value,
        new_port: Value,
    ) {
        let new_nickname = self.clean_sciter_string(new_nickname);
        let new_public_id = self.clean_sciter_string(new_public_id);
        let new_ip = self.clean_sciter_string(new_ip);
        let new_port = self.clean_sciter_string(new_port);

        println!("{}", new_nickname);
        println!("{}", new_public_id);
        println!("{}", new_ip);
        println!("{}", new_port);
    }
}

impl sciter::EventHandler for Handler {
    dispatch_script_call! {
        fn add_files(Value);
        fn add_folder(Value);
        fn add_new_user(Value, Value, Value, Value);
        fn add_user_to_shared(Value, Value);
        fn create_new_id();
        fn download_selected(Value);
        fn downloads_open();
        fn downloads_clear_finished();
        fn downloads_clear_finished_from_me();
        fn downloads_cancel_invalid();
        fn downloads_cancel_all();
        fn downloads_pause_all();
        fn downloads_resume_all();

        fn refresh_shared_with_me();
        fn remove_file_from_sharing(Value);
        fn remove_user(Value);
        fn remove_user_from_sharing(Value);

        fn get_app_display_name();
        fn get_app_display_version();
        fn get_app_url();

        fn get_downloads_in_progress();
        fn get_local_ip();
        fn get_my_sharing_state();
        fn get_shared_users();
        fn get_sharing_port();
        fn get_public_id_string();

        fn open_a_download(Value);

        fn set_my_sharing_state(Value);
        fn set_port(Value);
        fn set_user_is_allowed_state(Value, Value);
        fn update_user(Value, Value, Value, Value);

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
    println!("Sciter path: '{}'", sciter_string);
    println!("Transmitic Path: '{:?}'", env::current_exe().unwrap());

    let mut frame = get_sciter_frame();

    let transmitic_core: TransmiticCore;
    match TransmiticCore::new() {
        Ok(t) => {
            transmitic_core = t;
        }
        Err(e) => {
            let html_error = format!("Transmitic failed to start<br>{}", &e.to_string());
            frame.load_html(&html_error.into_bytes(), Some("example://main.htm"));
            frame.run_app();
            panic!("{:?}", e.to_string());
        }
    }

    let mut handler = Handler { transmitic_core };

    frame.event_handler(handler);
    frame.load_file(&sciter_string);
    frame.run_app();
}

fn get_sciter_frame() -> sciter::Window {
    sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_SYSINFO as u8
            | sciter::SCRIPT_RUNTIME_FEATURES::ALLOW_FILE_IO as u8,
    ))
    .unwrap();
    sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();

    let frame = sciter::Window::new();

    if cfg!(target_os = "macos") {
        frame
            .set_options(sciter::window::Options::DebugMode(true))
            .unwrap();
    }

    return frame;
}
