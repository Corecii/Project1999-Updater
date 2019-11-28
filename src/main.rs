
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate zip;

use regex::Regex;

use bytes::{Bytes, IntoBuf};

use hyper_tls::HttpsConnector;
use hyper::{Client};

use futures_util::TryStreamExt;

use select::document::Document;
use select::predicate::{Name};

use std::path::Path;

use std::io::{self, Read, Write};
use std::fs;

use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Deserialize, Serialize, Debug)]
struct P99Version {
    version: String,
}

fn read_current_version() -> Result<Option<P99Version>> {

    let path = Path::new("updater_version.json");

    if !path.is_file() {
        return Ok(None);
    }

    let contents = fs::read_to_string(path)?;

    let json_res: P99Version = serde_json::from_str(&contents)?;

    Ok(Some(json_res))
}

fn write_current_version(version: P99Version) -> Result<()> {
    let path = Path::new("updater_version.json");

    let contents = serde_json::to_string(&version)?;

    fs::write(path, contents)?;

    Ok(())
}

async fn find_latest_version_download(urls: Vec<String>) -> Result<Option<(String, String)>> {
    let https = HttpsConnector::new().unwrap();
    let client = Client::builder().build::<_, hyper::Body>(https);
        
    let mut best_url: String = "".to_string();
    let mut best_num: u32 = 0;
    let mut best_alpha: String = "".to_string();
    let mut best_name: String = "".to_string();

    for url in urls {
        let res_fut = client.get(url.parse().unwrap());

        let response = res_fut.await?;
        let body: hyper::Chunk = response.into_body().try_concat().await?;
        let body_str = String::from_utf8_lossy(&body.into_bytes()).to_string();

        let document = Document::from(&body_str[..]);

        let matches = document.find(Name("a"));

        for a_match in matches {
            let href = a_match.attr("href");
            if href.is_some() {
                let href = href.unwrap();
                lazy_static! {
                    static ref P99_PATH_REGEX: Regex = Regex::new(r"https?://www.project1999.com/files/P99Files((\d+)(\w*)).zip").unwrap();
                }
                for caps in P99_PATH_REGEX.captures_iter(href) {
                    let full_url = caps[0].to_string();
                    let num = caps[2].parse::<u32>().unwrap_or(0);
                    let alpha = caps[3].to_string();
                    if full_url != best_url {
                        if num > best_num || (num == best_num && alpha > best_alpha) {
                            best_url = full_url;
                            best_num = num;
                            best_alpha = alpha;
                            best_name = caps[1].to_string();
                        }
                    }
                }
            }
        }
    }

    if best_num > 0 {
        Ok(Some((best_url, best_name)))
    }
    else {
        Ok(None)
    }
}

async fn download_zip(url: &str) -> Result<Bytes> {
    let https = HttpsConnector::new().unwrap();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let res_fut = client.get(url.parse().unwrap());

    let response = res_fut.await?;
    let body: hyper::Chunk = response.into_body().try_concat().await?;
    let body_bytes = body.into_bytes();

    Ok(body_bytes)
}

fn apply_zip(bytes: Bytes) -> Result<()> {

    let reader = bytes.into_buf();

    let mut archive = zip::ZipArchive::new(reader)?;

    let len = archive.len();
    print!("0%");
    io::stdout().flush().unwrap();

    for i in 0..archive.len() {
        let percentage = i*100/len;
        print!("\r{}%", percentage);
        io::stdout().flush().unwrap();

        let mut file = archive.by_index(i).unwrap();
        let outpath = file.sanitized_name();

        if (&*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath).unwrap();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p).unwrap();
                }
            }   
            let mut outfile = fs::File::create(&outpath).unwrap();
            io::copy(&mut file, &mut outfile).unwrap();
        }

        // Get and Set permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }
    println!("\r100%");

    Ok(())
}

fn launch(close_window: bool) -> () {
    let mut close_window = close_window;
    let result = Command::new("eqgame").arg("patchme").spawn();
    if result.is_err() {
        println!("Failed to launch game because: {}", result.unwrap_err());
        close_window = false;
    }
    if !close_window {
        println!("Press any key to exit...");
        io::stdin().read(&mut [0]).unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Checking for update...");
    // removed "https://www.project1999.com/".to_string(), because beta news is published there.
    let val = find_latest_version_download(vec!["https://www.project1999.com/forums/showthread.php?t=2651".to_string()]).await;
    if val.is_err() {
        println!("Failed to check for update because: {}", val.unwrap_err());
        println!("\n\nIs your internet working okay?\n\nLaunching game anyway...");
        launch(false);
        return Ok(());
    }
    let file_url = val.unwrap();
    if file_url.is_none() {
        println!("No update files found.\n\nLaunching game...");
        launch(true);
        return Ok(());
    }
    let (file_url, file_version) = file_url.unwrap();

    let current_version = read_current_version();
    if current_version.is_err() {
        println!("Failed to read current version file (updater_version.json) because: {}", current_version.unwrap_err());
        println!("\n\nLaunching game anyway...");
        launch(false);
        return Ok(());
    }

    let current_version = current_version.unwrap();
    if current_version.is_some() {
        let current_version = current_version.unwrap();
        lazy_static! {
            static ref P99_VER_REGEX: Regex = Regex::new(r"(\d+)(\w*)").unwrap();
        }
        let current_caps = P99_VER_REGEX.captures(&current_version.version);
        let new_caps = P99_VER_REGEX.captures(&file_version);
        if current_caps.is_none() || new_caps.is_none() {
            println!("Cannot compare old and new versions. Did the version format change? Trying to compare old version {} to new version {}", current_version.version, file_version);
            println!("\n\nLaunching game anyway...");
            launch(false);
            return Ok(());
        }
        let (current_caps, new_caps) = (current_caps.unwrap(), new_caps.unwrap());
        let (current_num, new_num) = (current_caps[1].parse::<u32>().unwrap_or(0), new_caps[1].parse::<u32>().unwrap_or(0));
        let (current_alpha, new_alpha) = (current_caps[2].to_string(), new_caps[2].to_string());
        
        if new_num < current_num || (new_num == current_num && new_alpha <= current_alpha) {
            println!("No new update found.\n\nLaunching game...");
            launch(true);
            return Ok(());
        }

        println!("Found update: {} -> {}", current_version.version, file_version);
    } else {
        println!("Found update: {}", file_version);
    }

    println!("Update to {}? Y(es)/N(o) [Default: No]", file_version);

    let mut choice = String::new();
    match io::stdin().read_line(&mut choice) {
        Ok(_line) => {
            if choice.trim().to_lowercase() != "y" && choice.trim().to_lowercase() != "yes" {
                println!("Ignoring update.\n\nLaunching game...");
                launch(true);
                return Ok(());
            }
        }
        Err(e) => {
            println!("Failed to read line because: {}", e);
            println!("\n\nLaunching game anyway...");
            launch(true);
            return Ok(());
        }
    }
    
    let file_url = file_url.replace("http://", "https://");

    println!("Downloading file {}. This might take a while...", &file_url);

    let zip_data = download_zip(&file_url).await;
    if zip_data.is_err() {
        println!("Failed to download zip file ({}) because: {}", &file_url, zip_data.unwrap_err());
        println!("\n\nLaunching game anyway...");
        launch(false);
        return Ok(());
    }

    let zip_data = zip_data.unwrap();
    
    println!("Done downloading zip file.");
    println!("Applying zip file. This might take a while...");

    let zip_apply_result = apply_zip(zip_data);

    if zip_apply_result.is_err() {
        println!("Failed to apply zip file because: {}", zip_apply_result.unwrap_err());
        println!("\n\nZip might be half-applied and cause bugs! Please apply the update manually.");
        println!("\n\nLaunching game anyway...");
        launch(false);
        return Ok(());
    }

    println!("Done applying zip file.");

    let new_version = P99Version {version: file_version.to_string()};
    let write_version_result = write_current_version(new_version);

    let write_ver_err = write_version_result.is_err();
    if write_ver_err {
        println!("Failed to save current version because: {}", write_version_result.unwrap_err());
        println!("\n\nThis update will be re-applied every time you launch the game untill this issue is fixed.\n\n");
    }

    println!("Updated to version {}", &file_version);

    println!("Launching game...");
    launch(!write_ver_err);
    Ok(())
}