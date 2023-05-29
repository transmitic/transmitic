#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::cell::RefCell;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::str;
use std::str::FromStr;

use sciter::dispatch_script_call;
use sciter::RuntimeOptions;
use sciter::Value;
use serde::{Deserialize, Serialize};
use transmitic_core::config::create_config_dir;
use transmitic_core::config::get_path_config_json;
use transmitic_core::config::get_path_encrypted_config;
use transmitic_core::config::Config;
use transmitic_core::incoming_uploader::IncomingUploaderError;
use transmitic_core::incoming_uploader::SharingState;
use transmitic_core::logger::LogLevel;
use transmitic_core::shared_file::SelectedDownload;
use transmitic_core::shared_file::SharedFile;
use transmitic_core::transmitic_core::SingleUploadState;
use transmitic_core::transmitic_core::TransmiticCore;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = "Transmitic Beta";
const URL: &str = "https://transmitic.net";

struct ConfigData {
    password: Option<String>,
    config: Option<Config>,
}

struct ConfigHandler {
    config_data: Rc<RefCell<ConfigData>>,
    is_new_config: bool,
}

impl ConfigHandler {
    pub fn new(config_data: Rc<RefCell<ConfigData>>, is_new_config: bool) -> Self {
        ConfigHandler {
            config_data,
            is_new_config,
        }
    }
}

impl ConfigHandler {
    fn is_new_config(&self) -> Value {
        Value::from(self.is_new_config)
    }

    fn set_config_password(&mut self, password: Value, retype_password: Value) -> Value {
        let password = clean_sciter_string_no_trim(password);
        let retype_password = clean_sciter_string_no_trim(retype_password);

        let is_valid = transmitic_core::config::is_new_password_valid(&password, &retype_password);

        match is_valid {
            Ok(_) => {
                let mut reference = self.config_data.borrow_mut();
                reference.password = Some(password);
                get_msg_box_response(0, "")
            }
            Err(e) => get_msg_box_response(1, &e.to_string()),
        }
    }

    fn unlock(&mut self, password: Value) -> Value {
        let password = clean_sciter_string_no_trim(password);

        match Config::new(false, Some(password.clone())) {
            Ok(c) => {
                let mut reference = self.config_data.borrow_mut();
                reference.password = Some(password);

                reference.config = Some(c);
                get_msg_box_response(0, "")
            }
            Err(e) => get_msg_box_response(
                1,
                &format!("Failed to unlock. Double check your password. {}", e),
            ),
        }
    }
}

impl sciter::EventHandler for ConfigHandler {
    dispatch_script_call! {

        fn is_new_config();
        fn set_config_password(Value, Value);
        fn unlock(Value);
    }
}

struct TransmiticHandler {
    transmitic_core: TransmiticCore,
}

impl TransmiticHandler {
    pub fn new(transmitic_core: TransmiticCore) -> Self {
        TransmiticHandler { transmitic_core }
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
    in_progress: bool,
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
    pub size: String,
    pub error: String,
}

impl TransmiticHandler {
    fn is_config_encrypted(&self) -> Value {
        Value::from(self.transmitic_core.is_config_encrypted())
    }

    fn decrypt_config(&mut self) -> Value {
        match self.transmitic_core.decrypt_config() {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        }
    }

    fn encrypt_config(&mut self, password: Value, retype_password: Value) -> Value {
        let password = clean_sciter_string_no_trim(password);
        let retype_password = clean_sciter_string_no_trim(retype_password);

        match transmitic_core::config::is_new_password_valid(&password, &retype_password) {
            Ok(_) => {}
            Err(e) => return get_msg_box_response(1, &e.to_string()),
        }

        match self.transmitic_core.encrypt_config(password) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        }
    }

    // When a sciter array is sent as its self, it's expanded into args and fails, but put it in
    // another array as a container, is fine.
    fn add_files(&mut self, files_double_array: Value) -> Value {
        let mut clean_strings: Vec<String> = Vec::new();

        let files = files_double_array.get(0); // Get the inner array, which actually has the files
        for file in files.into_iter() {
            let clean_file = clean_sciter_string(file);
            clean_strings.push(clean_file);
        }

        let response = match self.transmitic_core.add_files(clean_strings) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
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
        let new_nickname = clean_sciter_string(new_nickname);
        let new_public_id = clean_sciter_string(new_public_id);
        let new_ip = clean_sciter_string(new_ip);
        let new_port = clean_sciter_string(new_port);

        let response =
            match self
                .transmitic_core
                .add_new_user(new_nickname, new_public_id, new_ip, new_port)
            {
                Ok(_) => get_msg_box_response(0, ""),
                Err(e) => get_msg_box_response(1, &e.to_string()),
            };
        response
    }

    fn add_user_to_shared(&mut self, nickname: Value, file_path: Value) -> Value {
        let nickname = clean_sciter_string(nickname);
        let mut file_path = clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\"); // TODO stdlib function for normalizing file paths?

        let response = match self.transmitic_core.add_user_to_shared(nickname, file_path) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn create_new_id(&mut self) -> Value {
        let response = match self.transmitic_core.create_new_id() {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn download_selected(&mut self, files: Value) -> Value {
        let files = files.get_item("files");

        let mut downloads: Vec<SelectedDownload> = Vec::new();
        for file in files.values() {
            let owner = clean_sciter_string(file.get_item("owner"));
            let mut path = clean_sciter_string(file.get_item("path"));
            path = unescape_path(&path);
            path = path.replace("\\\\", "\\");
            let new_download = SelectedDownload { path, owner };
            downloads.push(new_download);
        }

        let response = match self.transmitic_core.download_selected(downloads) {
            Ok(_) => get_msg_box_response(0, "Files will be downloaded"),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };
        response
    }

    fn open_in_file_explorer(&self, path: String) {
        let binary: String;

        if cfg!(target_os = "windows") {
            binary = "explorer.exe".to_owned();
        } else if cfg!(target_os = "macos") {
            binary = "open".to_owned();
        } else {
            binary = "xdg-open".to_owned();
        }

        Command::new(binary).arg(path).spawn().ok();
    }

    fn downloads_open(&self) {
        let dir_path = self.transmitic_core.get_downloads_dir().unwrap();
        self.open_in_file_explorer(dir_path.to_string_lossy().to_string());
    }

    fn downloads_open_single(&self, path_local_disk: Value) {
        let mut path_local_disk = clean_sciter_string(path_local_disk);
        path_local_disk = unescape_path(&path_local_disk);

        if cfg!(target_family = "windows") {
            path_local_disk = path_local_disk.replace("\\\\", "\\");
            if let Some(s) = path_local_disk.strip_suffix('\\') {
                path_local_disk = s.to_string()
            }
        }

        self.open_in_file_explorer(path_local_disk);
    }

    fn downloads_clear_finished(&mut self) {
        self.transmitic_core.downloads_clear_finished();
    }

    fn downloads_clear_finished_from_me(&mut self) {
        self.transmitic_core.downloads_clear_finished_from_me();
    }

    fn downloads_clear_invalid(&mut self) {
        self.transmitic_core.downloads_clear_invalid();
    }

    fn downloads_cancel_all(&mut self) {
        self.transmitic_core.downloads_cancel_all();
    }

    fn downloads_cancel_single(&mut self, nickname: Value, file_path: Value) {
        let nickname = clean_sciter_string(nickname);
        let mut file_path = clean_sciter_string(file_path);
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
                            .unwrap_or_default();

                        if cfg!(target_family = "windows") {
                            path_local_disk = path_local_disk.replace('/', "\\");
                        }

                        in_progress.push(SingleDownloadUI {
                            owner: nickname.clone(),
                            percent: download_state.active_download_percent,
                            path: path.clone(),
                            path_local_disk,
                            size: download_state.active_download_size.clone(),
                            error: "".to_string(),
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
                        size: "".to_string(),
                        error: "".to_string(),
                    });
                }
            } else {
                for queued_download in download_state.download_queue.iter() {
                    offline.push(SingleDownloadUI {
                        owner: nickname.clone(),
                        percent: 0,
                        path: queued_download.clone(),
                        path_local_disk: "".to_string(),
                        size: "".to_string(),
                        error: download_state.error.clone().unwrap_or_default(),
                    });
                }
            }

            for invalid_download in download_state.invalid_downloads.iter() {
                invalid.push(SingleDownloadUI {
                    owner: nickname.clone(),
                    percent: 0,
                    path: invalid_download.clone(),
                    path_local_disk: "".to_string(),
                    size: "".to_string(),
                    error: "".to_string(),
                });
            }

            for finished_download in download_state.completed_downloads.iter() {
                let mut path_local_disk = finished_download.path_local_disk.clone();

                if cfg!(target_family = "windows") {
                    path_local_disk = path_local_disk.replace('/', "\\");
                }

                completed.push(SingleDownloadUI {
                    owner: nickname.clone(),
                    percent: 100,
                    path: finished_download.path.clone(),
                    path_local_disk,
                    size: finished_download.size_string.clone(),
                    error: "".to_string(),
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

    fn get_log_path(&self) -> Value {
        let path = self.transmitic_core.get_log_path();
        let mut p = path.as_os_str().to_string_lossy().to_string();

        let i = 4;
        if p.starts_with("\\\\?\\") && p.len() > i {
            p = p[i..].to_string();
        }
        Value::from(p)
    }

    fn get_log_messages(&self) -> Value {
        let log_messages = self.transmitic_core.get_log_messages();
        let mut value_messages = Value::new();

        let max = 200; // Sciter won't show after 400 strings, so max at 200 to be safe
        for (count, message) in log_messages.into_iter().enumerate() {
            if count >= max {
                break;
            }
            value_messages.push(message);
        }
        value_messages
    }

    // TODO can the UI load possible values from a function so it isn't hard coded in HTML?
    fn get_log_level(&self) -> Value {
        let log_level = self.transmitic_core.get_log_level();
        let level = match log_level {
            LogLevel::Critical => "CRITICAL",
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARNING",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        };
        Value::from(level)
    }

    fn set_log_level(&mut self, log_level: Value) -> Value {
        let log_level = clean_sciter_string(log_level);

        // TODO hardcoded strings with get_log_level
        // Can this be in an enum with match?
        let mut response = get_msg_box_response(0, "");
        let log_enum;
        if log_level == "CRITICAL" {
            log_enum = LogLevel::Critical;
        } else if log_level == "ERROR" {
            log_enum = LogLevel::Error;
        } else if log_level == "WARNING" {
            log_enum = LogLevel::Warning;
        } else if log_level == "INFO" {
            log_enum = LogLevel::Info;
        } else if log_level == "DEBUG" {
            log_enum = LogLevel::Debug;
        } else {
            log_enum = LogLevel::Debug;
            response = get_msg_box_response(
                1,
                &format!("Unknown log level '{}'. Defaulting to DEBUG.", log_level),
            );
        }
        self.transmitic_core.set_log_level(log_enum);

        response
    }

    fn is_log_to_file(&self) -> Value {
        Value::from(self.transmitic_core.is_log_to_file())
    }

    fn log_to_file_start(&mut self) {
        self.transmitic_core.log_to_file_start();
    }

    fn log_to_file_stop(&mut self) {
        self.transmitic_core.log_to_file_stop();
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
        get_msg_box_response(0, &state)
    }

    fn is_ignore_incoming(&self) -> Value {
        Value::from(self.transmitic_core.is_ignore_incoming())
    }

    fn is_reverse_connection(&self) -> Value {
        Value::from(self.transmitic_core.is_reverse_connection())
    }

    fn get_and_reset_my_sharing_error(&mut self) -> Value {
        let error = self.transmitic_core.get_and_reset_my_sharing_error();

        match error {
            Some(error) => match error {
                IncomingUploaderError::PortInUse => get_msg_box_response(
                    1,
                    "Port already in use. Sharing stopped. Choose another port.",
                ),
                IncomingUploaderError::Generic(string) => {
                    get_msg_box_response(1, &format!("Sharing stopped. {}", string))
                }
            },
            None => get_msg_box_response(0, ""),
        }
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

    fn get_shared_with_me_data(&mut self) -> Value {
        let refresh_data = self.transmitic_core.get_shared_with_me_data();

        let mut ui_data = Vec::new();
        for (nickname, data) in refresh_data.iter() {
            let files = match &data.data {
                Some(shared_file) => vec![shared_file.clone()],
                None => vec![],
            };
            let ui = RefreshDataUI {
                owner: nickname.to_string(),
                error: data.error.clone().unwrap_or("".to_string()),
                files,
                in_progress: data.in_progress,
            };
            ui_data.push(ui);
        }

        ui_data.sort_by(|f, g| f.owner.cmp(&g.owner));

        let json_string = serde_json::to_string_pretty(&ui_data).unwrap();
        Value::from_str(&json_string).unwrap()
    }

    fn start_refresh_shared_with_me_all(&mut self) {
        self.transmitic_core.start_refresh_shared_with_me_all();
    }

    fn start_refresh_shared_with_me_single_user(&mut self, nickname: Value) {
        let nickname = clean_sciter_string(nickname);
        self.transmitic_core
            .start_refresh_shared_with_me_single_user(nickname);
    }

    fn is_downloading_paused(&self) -> Value {
        Value::from(self.transmitic_core.is_downloading_paused())
    }

    fn remove_file_from_sharing(&mut self, file_path: Value) -> Value {
        let mut file_path = clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\");

        let response = match self.transmitic_core.remove_file_from_sharing(file_path) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn remove_user(&mut self, nickname: Value) -> Value {
        let nickname = clean_sciter_string(nickname);
        let response = match self.transmitic_core.remove_user(nickname) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn remove_user_from_sharing(&mut self, nickname: Value, file_path: Value) -> Value {
        let nickname = clean_sciter_string(nickname);
        let mut file_path = clean_sciter_string(file_path);
        file_path = unescape_path(&file_path);
        file_path = file_path.replace("\\\\", "\\");

        let response = match self
            .transmitic_core
            .remove_user_from_sharing(nickname, file_path)
        {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn set_my_sharing_state(&mut self, state: Value) -> Value {
        let state = clean_sciter_string(state);

        let core_state: SharingState;
        if state == "Off" {
            core_state = SharingState::Off;
        } else if state == "Local" {
            core_state = SharingState::Local;
        } else if state == "Internet" {
            core_state = SharingState::Internet;
        } else {
            return get_msg_box_response(1, &format!("Sharing state '{}' is not valid", state));
        }

        self.transmitic_core.set_my_sharing_state(core_state);
        get_msg_box_response(0, "")
    }

    fn set_ignore_incoming(&mut self, state: Value) -> Value {
        let state = state.to_bool().unwrap();
        let response = match self.transmitic_core.set_ignore_incoming(state) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn set_reverse_connection(&mut self, state: Value) -> Value {
        let state = state.to_bool().unwrap();
        let response = match self.transmitic_core.set_reverse_connection(state) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn set_port(&mut self, port: Value) -> Value {
        let port = clean_sciter_string(port);

        let response = match self.transmitic_core.set_port(port) {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
        };

        response
    }

    fn set_user_is_allowed_state(&mut self, nickname: Value, is_allowed: Value) -> Value {
        let nickname = clean_sciter_string(nickname);
        let is_allowed = match is_allowed.to_bool() {
            Some(is_allowed) => is_allowed,
            None => return get_msg_box_response(1, "is_allowed is not a bool"),
        };

        let response = match self
            .transmitic_core
            .set_user_is_allowed_state(nickname, is_allowed)
        {
            Ok(_) => get_msg_box_response(0, ""),
            Err(e) => get_msg_box_response(1, &e.to_string()),
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
        let nickname = clean_sciter_string(nickname);
        let new_public_id = clean_sciter_string(new_public_id);
        let new_ip = clean_sciter_string(new_ip);
        let new_port = clean_sciter_string(new_port);

        let response =
            match self
                .transmitic_core
                .update_user(nickname, new_public_id, new_ip, new_port)
            {
                Ok(_) => get_msg_box_response(0, ""),
                Err(e) => get_msg_box_response(1, &e.to_string()),
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

#[allow(clippy::mixed_read_write_in_expression)]
impl sciter::EventHandler for TransmiticHandler {
    dispatch_script_call! {

        fn is_config_encrypted();
        fn decrypt_config();
        fn encrypt_config(Value, Value);

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

        fn remove_file_from_sharing(Value);
        fn remove_user(Value);
        fn remove_user_from_sharing(Value, Value);

        fn get_app_display_name();
        fn get_app_display_version();
        fn get_app_url();

        fn is_log_to_file();
        fn log_to_file_start();
        fn log_to_file_stop();
        fn get_log_path();
        fn get_log_messages();
        fn get_log_level();
        fn set_log_level(Value);

        fn get_all_downloads();
        fn get_all_uploads();
        fn get_is_first_start();
        fn get_my_sharing_files();
        fn get_my_sharing_state();
        fn is_ignore_incoming();
        fn set_ignore_incoming(Value);
        fn is_reverse_connection();
        fn set_reverse_connection(Value);
        fn get_and_reset_my_sharing_error();
        fn get_shared_with_me_data();
        fn start_refresh_shared_with_me_all();
        fn start_refresh_shared_with_me_single_user(Value);
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

    let config_start_path: PathBuf;
    let main_path: PathBuf;
    if cfg!(debug_assertions) {
        println!("DEBUG BUILD");
        let mut base = env::current_dir().unwrap();
        base.push("transmitic\\src\\");

        main_path = base.join("main.htm");
        config_start_path = base.join("config_start.htm");
    } else {
        println!("Release");
        let sciter_path = env::current_exe().unwrap();
        let sciter_path = sciter_path.parent().unwrap();
        let sciter_path = sciter_path.join("res");

        main_path = sciter_path.join("main.htm");
        config_start_path = sciter_path.join("config_start.htm");
    }

    let main_path: String = format!("file://{}", main_path.to_string_lossy());
    let config_start_path: String = format!("file://{}", config_start_path.to_string_lossy());

    println!("Current Working Dir: '{:?}'", env::current_dir().unwrap());
    println!("Sciter path: '{}'", main_path);
    println!("Config start path: '{}'", config_start_path);
    println!("Transmitic Path: '{:?}'", env::current_exe().unwrap());

    let config = match initialize_config(&config_start_path) {
        Ok(c) => c,
        Err(e) => {
            let html_error = format!("Transmitic failed to load config<br>{}", &e.to_string());
            let mut frame = get_sciter_frame();
            frame.load_html(&html_error.into_bytes(), Some("example://main.htm"));
            frame.run_app();
            panic!("{:?}", e.to_string());
        }
    };

    let transmitic_core: TransmiticCore = match TransmiticCore::new(config) {
        Ok(t) => t,
        Err(e) => {
            let html_error = format!("Transmitic failed to start<br>{}", &e.to_string());
            let mut frame = get_sciter_frame();
            frame.load_html(&html_error.into_bytes(), Some("example://main.htm"));
            frame.run_app();
            panic!("{:?}", e.to_string());
        }
    };

    let handler = TransmiticHandler::new(transmitic_core);
    let mut frame = get_sciter_frame();
    frame.event_handler(handler);
    frame.load_file(&main_path);
    frame.run_app();
}

fn get_sciter_frame() -> sciter::Window {
    if cfg!(debug_assertions) {
        sciter::set_options(sciter::RuntimeOptions::DebugMode(true)).unwrap();
    }
    match sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::SKIA_CPU,
    )) {
        Ok(_) => {}
        Err(_) => {
            eprintln!("Transmitic: sciter failed to set SKIA_OPENGL");
        }
    }

    sciter::Window::new()
}

fn clean_sciter_string_no_trim(s: Value) -> String {
    let mut s = s.to_string();
    s = s[1..s.len() - 1].to_string();
    s
}

fn clean_sciter_string(s: Value) -> String {
    let mut s = clean_sciter_string_no_trim(s);
    s = s.trim().to_string();
    s
}

fn get_msg_box_response(code: i32, msg: &str) -> Value {
    let mut response = Value::new();

    response.push(Value::from(code));
    response.push(Value::from(msg));
    response
}

fn initialize_config(config_start_path: &str) -> Result<Config, Box<dyn Error>> {
    create_config_dir()?;
    let config_data = Rc::new(RefCell::new(ConfigData {
        password: None,
        config: None,
    }));

    let json_path = get_path_config_json()?;
    let encrypted_path = get_path_encrypted_config()?;
    let json_exists = json_path.exists();
    let encrypted_exists = encrypted_path.exists();
    let mut is_new_config = false;

    if json_exists && encrypted_exists {
        Err(format!(
            "Encrypted config and unencrypted config both exist. Only one may exist. '{}' and '{}'",
            json_path.to_string_lossy(),
            encrypted_path.to_string_lossy()
        ))?;
    } else if json_exists {
    } else {
        if !encrypted_exists {
            is_new_config = true;
        }
        let mut frame = get_sciter_frame();
        let handler = ConfigHandler::new(Rc::clone(&config_data), is_new_config);
        frame.event_handler(handler);
        frame.load_file(config_start_path);
        frame.run_app();

        let mut password = config_data.borrow().password.clone();

        // Unlock attempt with empty string
        if password == Some("".to_string()) {
            password = None;
        }

        // Window closed
        if password.is_none() && encrypted_exists {
            std::process::exit(0);
        }
    }

    let config = match config_data.borrow().config.clone() {
        Some(c) => c,
        None => Config::new(is_new_config, config_data.borrow().password.clone())?,
    };

    Ok(config)
}
