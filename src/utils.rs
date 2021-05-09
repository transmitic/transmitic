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


