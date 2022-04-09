use std::env;
use std::process::Command;
use std::str;
use std::str::FromStr;
use std::sync::mpsc::Receiver;

use serde::{Deserialize, Serialize};
extern crate sciter;
use sciter::dispatch_script_call;
use sciter::Value;
use transmitic_core::incoming_uploader::SharingState;
use transmitic_core::outgoing_downloader::RefreshSharedMessages;
use transmitic_core::shared_file::RefreshData;
use transmitic_core::shared_file::SelectedDownload;
use transmitic_core::shared_file::SharedFile;
use transmitic_core::transmitic_core::SingleUploadState;
use transmitic_core::transmitic_core::TransmiticCore;

const VERSION: &str = "0.10.0"; // Note: And cargo.toml
const NAME: &str = "Transmitic Beta";
const URL: &str = "https://transmitic.net";

struct Handler {
    transmitic_core: TransmiticCore,
    refresh_is_inprogress: bool,
    refresh_total_count: usize,
    refresh_data: Vec<RefreshData>,
    refresh_recv: Option<Receiver<RefreshSharedMessages>>,
}

impl Handler {
    pub fn new(transmitic_core: TransmiticCore) -> Self {
        Handler {
            transmitic_core,
            refresh_is_inprogress: false,
            refresh_total_count: 0,
            refresh_data: Vec::new(),
            refresh_recv: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct FilesJson {
    files: Vec<PathJson>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PathJson {
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RefreshDataUI {
    owner: String,
    error: String,
    files: Vec<SharedFile>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AllDownloadsUI {
    is_downloading_paused: bool,
    in_progress: Vec<SingleDownloadUI>,
    invalid: Vec<SingleDownloadUI>,
    queued: Vec<SingleDownloadUI>,
    offline: Vec<SingleDownloadUI>,
    finished: Vec<SingleDownloadUI>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SingleDownloadUI {
    pub owner: String,
    pub percent: u64,
    pub path: String,
    pub path_local_disk: String,
}

impl Handler {
    // When a sciter array is sent as its self, it's expanded into args and fails, but put it in
    // another array as a container, is fine.
    fn add_files(&mut self, files_double_array: Value) -> Value {
        let mut clean_strings: Vec<String> = Vec::new();

        let files = files_double_array.get(0); // Get the inner array, which actually has the files
        for file in files.into_iter() {
            let clean_file = self.clean_sciter_string(file);
            clean_strings.push(clean_file);
        }

        let response = match self.transmitic_core.add_files(clean_strings) {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn add_new_user(
        &mut self,
        new_nickname: Value,
        new_public_id: Value,
        new_ip: Value,
        new_port: Value,
    ) -> Value {
        let new_nickname = self.clean_sciter_string(new_nickname);
        let new_public_id = self.clean_sciter_string(new_public_id);
        let new_ip = self.clean_sciter_string(new_ip);
        let new_port = self.clean_sciter_string(new_port);

        let response =
            match self
                .transmitic_core
                .add_new_user(new_nickname, new_public_id, new_ip, new_port)
            {
                Ok(_) => self.get_msg_box_response(0, ""),
                Err(e) => self.get_msg_box_response(1, &e.to_string()),
            };
        response
    }

    fn add_user_to_shared(&mut self, nickname: Value, file_path: Value) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let mut file_path = self.clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\"); // TODO stdlib function for normalizing file paths?

        let response = match self.transmitic_core.add_user_to_shared(nickname, file_path) {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn create_new_id(&mut self) -> Value {
        let response = match self.transmitic_core.create_new_id() {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn download_selected(&mut self, files: Value) -> Value {
        let files = files.get_item("files");

        let mut downloads: Vec<SelectedDownload> = Vec::new();
        for file in files.values() {
            let owner = self.clean_sciter_string(file.get_item("owner"));
            let mut path = self.clean_sciter_string(file.get_item("path"));
            path = unescape_path(&path);
            path = path.replace("\\\\", "\\");
            let new_download = SelectedDownload { path, owner };
            downloads.push(new_download);
        }

        let response = match self.transmitic_core.download_selected(downloads) {
            Ok(_) => self.get_msg_box_response(0, "Files will be downloaded"),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn downloads_open(&self) {
        let dir_path = self.transmitic_core.get_downloads_dir().unwrap();
        Command::new("explorer.exe").arg(dir_path).spawn().ok();
    }

    fn downloads_open_single(&self, path_local_disk: Value) {
        let mut path_local_disk = self.clean_sciter_string(path_local_disk);
        path_local_disk = unescape_path(&path_local_disk);
        path_local_disk = path_local_disk.replace("\\\\", "\\");

        if let Some(s) = path_local_disk.strip_suffix('\\') {
            path_local_disk = s.to_string()
        }
        Command::new("explorer.exe")
            .arg(path_local_disk)
            .spawn()
            .ok();
    }

    fn downloads_clear_finished(&mut self) {
        self.transmitic_core.downloads_clear_finished();
    }

    fn downloads_clear_finished_from_me(&self) {}

    fn downloads_clear_invalid(&mut self) {
        self.transmitic_core.downloads_clear_invalid();
    }

    fn downloads_cancel_all(&mut self) {
        self.transmitic_core.downloads_cancel_all();
    }

    fn downloads_cancel_single(&mut self, nickname: Value, file_path: Value) {
        let nickname = self.clean_sciter_string(nickname);
        let mut file_path = self.clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\"); // TODO stdlib function for normalizing file paths?

        self.transmitic_core
            .downloads_cancel_single(nickname, file_path);
    }

    fn downloads_pause_all(&mut self) {
        self.transmitic_core.downloads_pause_all();
    }

    fn downloads_resume_all(&mut self) {
        self.transmitic_core.downloads_resume_all();
    }

    fn get_all_uploads(&self) -> Value {
        let upload_state = self.transmitic_core.get_upload_state();
        let u = upload_state.read().unwrap();

        let mut uploads: Vec<SingleUploadState> = u.values().cloned().collect();
        uploads.sort_by(|x, y| x.nickname.cmp(&y.nickname));

        let json_string = serde_json::to_string(&uploads).unwrap();
        Value::from_str(&json_string).unwrap()
    }

    fn get_all_downloads(&self) -> Value {
        let download_state_lock = self.transmitic_core.get_download_state();
        let d = download_state_lock.read().unwrap();

        let mut nicknames: Vec<String> = Vec::new();
        for key in d.keys() {
            nicknames.push(key.clone());
        }
        nicknames.sort();

        let mut in_progress: Vec<SingleDownloadUI> = Vec::new();
        let mut invalid: Vec<SingleDownloadUI> = Vec::new();
        let mut queued: Vec<SingleDownloadUI> = Vec::new();
        let mut completed: Vec<SingleDownloadUI> = Vec::new();
        let mut offline: Vec<SingleDownloadUI> = Vec::new();
        for nickname in nicknames {
            let download_state = d.get(&nickname).unwrap();

            if download_state.is_online {
                match &download_state.active_download_path {
                    Some(path) => {
                        let mut path_local_disk = download_state
                            .active_download_local_path
                            .clone()
                            .unwrap_or_else(|| "".to_string());
                        path_local_disk = path_local_disk.replace('/', "\\");
                        in_progress.push(SingleDownloadUI {
                            owner: nickname.clone(),
                            percent: download_state.active_download_percent,
                            path: path.clone(),
                            path_local_disk,
                        });
                    }
                    None => {} // Do nothing, there is no in progress download
                }

                for queued_download in download_state.download_queue.iter() {
                    queued.push(SingleDownloadUI {
                        owner: nickname.clone(),
                        percent: 0,
                        path: queued_download.clone(),
                        path_local_disk: "".to_string(),
                    });
                }
            } else {
                for queued_download in download_state.download_queue.iter() {
                    offline.push(SingleDownloadUI {
                        owner: nickname.clone(),
                        percent: 0,
                        path: queued_download.clone(),
                        path_local_disk: "".to_string(),
                    });
                }
            }

            for invalid_download in download_state.invalid_downloads.iter() {
                invalid.push(SingleDownloadUI {
                    owner: nickname.clone(),
                    percent: 0,
                    path: invalid_download.clone(),
                    path_local_disk: "".to_string(),
                });
            }

            for finished_download in download_state.completed_downloads.iter() {
                let mut path_local_disk = finished_download.path_local_disk.clone();
                path_local_disk = path_local_disk.replace('/', "\\");
                completed.push(SingleDownloadUI {
                    owner: nickname.clone(),
                    percent: 100,
                    path: finished_download.path.clone(),
                    path_local_disk,
                });
            }
        }

        let all_downloads = AllDownloadsUI {
            is_downloading_paused: self.transmitic_core.is_downloading_paused(),
            in_progress,
            invalid,
            queued,
            offline,
            finished: completed,
        };

        let json_string = serde_json::to_string(&all_downloads).unwrap();
        Value::from_str(&json_string).unwrap()
    }

    fn get_msg_box_response(&self, code: i32, msg: &str) -> Value {
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

    fn get_app_display_name(&self) -> Value {
        Value::from(NAME)
    }

    fn get_app_display_version(&self) -> Value {
        Value::from(format!("v{}", VERSION))
    }

    fn get_app_url(&self) -> Value {
        Value::from(URL)
    }

    fn get_is_first_start(&self) -> Value {
        Value::from(self.transmitic_core.get_is_first_start())
    }

    fn get_my_sharing_files(&self) -> Value {
        let my_sharing_files = self.transmitic_core.get_my_sharing_files();
        let mut shared_users = Vec::new();
        for user in self.transmitic_core.get_shared_users() {
            shared_users.push(user.nickname);
        }

        // TODO Use struct and serde to clean this up
        let mut my_files = Value::array(0);
        for file in my_sharing_files {
            let mut new_file = Value::new();
            new_file.set_item("file_path", file.path);

            let mut shared_with = Value::array(0);
            for s in file.shared_with.iter() {
                shared_with.push(s);
            }
            new_file.set_item("shared_with", shared_with);

            let mut add_users = Value::array(0);
            for user in shared_users.iter() {
                if !file.shared_with.contains(user) {
                    add_users.push(user.clone());
                }
            }
            new_file.set_item("add_users", add_users);

            my_files.push(new_file);
        }

        my_files
    }

    fn get_my_sharing_state(&self) -> Value {
        let state = match self.transmitic_core.get_my_sharing_state() {
            SharingState::Off => "Off".to_string(),
            SharingState::Local => "Local".to_string(),
            SharingState::Internet => "Internet".to_string(),
        };
        self.get_msg_box_response(0, &state)
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

        user_list
    }

    fn get_sharing_port(&self) -> Value {
        let sharing_port = self.transmitic_core.get_sharing_port();
        Value::from(sharing_port)
    }

    fn get_public_id_string(&self) -> Value {
        let public_id_string = self.transmitic_core.get_public_id_string();
        Value::from(public_id_string)
    }

    // TODO switch the channel with Arc mutex, would that be simpler?
    fn start_refresh_shared_with_me(&mut self) -> Value {
        if self.refresh_is_inprogress {
            return Value::from(self.refresh_total_count.to_string());
        }

        let refresh_data = self.transmitic_core.refresh_shared_with_me();
        self.refresh_is_inprogress = true;
        self.refresh_total_count = refresh_data.0;
        self.refresh_recv = Some(refresh_data.1);
        self.refresh_data.clear();

        Value::from(self.refresh_total_count.to_string())
    }

    fn get_refresh_state(&mut self) -> Value {
        let recv = match &self.refresh_recv {
            Some(recv) => recv,
            None => panic!("called refresh.recv on None"),
        };

        loop {
            match recv.try_recv() {
                Ok(msg) => match msg {
                    RefreshSharedMessages::UIData(data) => self.refresh_data.push(data),
                    RefreshSharedMessages::RefreshFinished => {
                        self.refresh_is_inprogress = false;
                        break;
                    }
                },
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => break,
                    std::sync::mpsc::TryRecvError::Disconnected => {
                        self.refresh_is_inprogress = false;
                        break;
                    }
                },
            }
        }

        let mut response = Value::new();
        response.push(self.refresh_is_inprogress);
        response.push(self.refresh_data.len().to_string());
        response
    }

    fn is_downloading_paused(&self) -> Value {
        Value::from(self.transmitic_core.is_downloading_paused())
    }

    fn refresh_shared_with_me(&mut self) -> Value {
        let mut ui_data = Vec::new();
        for data in self.refresh_data.iter() {
            let ui: RefreshDataUI = match data.data.clone() {
                Ok(file) => RefreshDataUI {
                    owner: data.owner.clone(),
                    error: "".to_string(),
                    files: vec![file],
                },
                Err(e) => RefreshDataUI {
                    owner: data.owner.clone(),
                    error: e.to_string(),
                    files: Vec::new(),
                },
            };
            ui_data.push(ui);
        }

        let json_string = serde_json::to_string_pretty(&ui_data).unwrap();
        Value::from_str(&json_string).unwrap()
    }

    fn remove_file_from_sharing(&mut self, file_path: Value) -> Value {
        let mut file_path = self.clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\");

        let response = match self.transmitic_core.remove_file_from_sharing(file_path) {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn remove_user(&mut self, nickname: Value) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let response = match self.transmitic_core.remove_user(nickname) {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn remove_user_from_sharing(&mut self, nickname: Value, file_path: Value) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let mut file_path = self.clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\");

        let response = match self
            .transmitic_core
            .remove_user_from_sharing(nickname, file_path)
        {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn set_my_sharing_state(&mut self, state: Value) -> Value {
        let state = self.clean_sciter_string(state);

        let core_state: SharingState;
        if state == "Off" {
            core_state = SharingState::Off;
        } else if state == "Local" {
            core_state = SharingState::Local;
        } else if state == "Internet" {
            core_state = SharingState::Internet;
        } else {
            return self
                .get_msg_box_response(1, &format!("Sharing state '{}' is not valid", state));
        }

        self.transmitic_core.set_my_sharing_state(core_state);
        self.get_msg_box_response(0, "")
    }

    fn set_port(&mut self, port: Value) -> Value {
        let port = self.clean_sciter_string(port);

        let response = match self.transmitic_core.set_port(port) {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn set_user_is_allowed_state(&mut self, nickname: Value, is_allowed: Value) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let is_allowed = match is_allowed.to_bool() {
            Some(is_allowed) => is_allowed,
            None => return self.get_msg_box_response(1, "is_allowed is not a bool"),
        };

        let response = match self
            .transmitic_core
            .set_user_is_allowed_state(nickname, is_allowed)
        {
            Ok(_) => self.get_msg_box_response(0, ""),
            Err(e) => self.get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn update_user(
        &mut self,
        nickname: Value,
        new_public_id: Value,
        new_ip: Value,
        new_port: Value,
    ) -> Value {
        let nickname = self.clean_sciter_string(nickname);
        let new_public_id = self.clean_sciter_string(new_public_id);
        let new_ip = self.clean_sciter_string(new_ip);
        let new_port = self.clean_sciter_string(new_port);

        let response =
            match self
                .transmitic_core
                .update_user(nickname, new_public_id, new_ip, new_port)
            {
                Ok(_) => self.get_msg_box_response(0, ""),
                Err(e) => self.get_msg_box_response(1, &e.to_string()),
            };

        response
    }
}

fn unescape_path(path: &str) -> String {
    // TODO Need to update UI to say that the path was escaped to being with
    let mut unescaped_path = path.to_string();
    unescaped_path = unescaped_path.replace("&#039;", "'");
    unescaped_path = unescaped_path.replace("&amp;", "&");

    unescaped_path
}

#[allow(clippy::eval_order_dependence)]
impl sciter::EventHandler for Handler {
    dispatch_script_call! {

        fn add_files(Value);
        fn add_new_user(Value, Value, Value, Value);
        fn add_user_to_shared(Value, Value);
        fn create_new_id();
        fn download_selected(Value);
        fn downloads_open();
        fn downloads_open_single(Value);
        fn downloads_clear_finished();
        fn downloads_clear_finished_from_me();
        fn downloads_clear_invalid();
        fn downloads_cancel_all();
        fn downloads_cancel_single(Value, Value);
        fn downloads_pause_all();
        fn downloads_resume_all();

        fn refresh_shared_with_me();
        fn remove_file_from_sharing(Value);
        fn remove_user(Value);
        fn remove_user_from_sharing(Value, Value);

        fn get_app_display_name();
        fn get_app_display_version();
        fn get_app_url();

        fn get_all_downloads();
        fn get_all_uploads();
        fn get_is_first_start();
        fn get_my_sharing_files();
        fn get_my_sharing_state();
        fn start_refresh_shared_with_me();
        fn get_refresh_state();
        fn get_shared_users();
        fn get_sharing_port();
        fn get_public_id_string();
        fn is_downloading_paused();

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

    let sciter_string = if cfg!(debug_assertions) {
        println!("DEBUG BUILD");
        let mut sciter_path = env::current_dir().unwrap();
        sciter_path.push("transmitic\\src\\main.htm");
        format!("file://{}", sciter_path.to_string_lossy())
    } else {
        println!("Release");
        let sciter_path = env::current_exe().unwrap();
        let sciter_path = sciter_path.parent().unwrap();
        let sciter_path = sciter_path.join("res").join("main.htm");
        format!("file://{}", sciter_path.to_string_lossy())
    };

    println!("Current Working Dir: '{:?}'", env::current_dir().unwrap());
    println!("Sciter path: '{}'", sciter_string);
    println!("Transmitic Path: '{:?}'", env::current_exe().unwrap());

    let mut frame = get_sciter_frame();

    let transmitic_core: TransmiticCore = match TransmiticCore::new() {
        Ok(t) => t,
        Err(e) => {
            let html_error = format!("Transmitic failed to start<br>{}", &e.to_string());
            frame.load_html(&html_error.into_bytes(), Some("example://main.htm"));
            frame.run_app();
            panic!("{:?}", e.to_string());
        }
    };

    let handler = Handler::new(transmitic_core);

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

    if cfg!(debug_assertions) {
        sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();
    }

    let frame = sciter::Window::new();

    if cfg!(target_os = "macos") {
        frame
            .set_options(sciter::window::Options::DebugMode(true))
            .unwrap();
    }

    frame
}
