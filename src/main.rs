mod amzn_photo;
mod config;

use amzn_photo::AmznPhoto;
use config::Config;

use clap::Parser;
use env_logger::{Builder, Target};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Write}, path::Path, sync::Arc,
};
use tokio::sync::{Mutex, Semaphore};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The global album name to use for the upload
    #[arg(long)]
    album_name: Option<String>,

    /// Input path(s) to process - can be a file or directory. Can be specified multiple times.
    #[arg(long)]
    input: Vec<String>,

    /// Enable verbose mode
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Test that it works without actually running any network operation
    #[arg(long, action = clap::ArgAction::SetTrue)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    // Configure the logger programmatically
    let mut builder = Builder::new();

    // Set the target for log output (stdout, stderr, etc.)
    builder.target(Target::Stdout);

    // Set the logging level explicitly (e.g., Debug level)
    if args.verbose {
        builder.filter_level(log::LevelFilter::Debug);
    } else {
        builder.filter_level(log::LevelFilter::Info);
    }

    // Optional: Customize the log format
    builder.format(|buf, record| {
        writeln!(
            buf,
            "[{}] [{}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.args()
        )
    });

    // Initialize the logger
    builder.init();

    let mut conf = Config::load()?;
    let uploader = AmznPhoto::new(&mut conf, args.dry_run);
    let is_albumless: bool = args.album_name.is_none();

    if is_albumless {
        let mut input = String::new();
        loop {
            print!("Do you really want to upload without adding to a specific album? [y/N]: ");
            let _ = io::stdout().flush();
            io::stdin().read_line(&mut input).unwrap();
            if matches!(input.trim().to_lowercase().as_str(), "y" | "yes" | "n" | "no" | "") {
                break;
            }
        }
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => {
                // Don't do anything yet
            },
            "n" | "no" | "" => {
                return Ok(());
            },
            _ => { return Ok(());}
        }
    }

    let mut uploaded_ids: Vec<String> = Vec::new();
    let mut upload_album_id: String = "".to_string();
    let mut upload_album_owner_id: String = "".to_string();

    if is_albumless {

    } else {
        let album_ref = &uploader.get_album(&args.album_name.unwrap()).await;

        info!("Getting the album reference...");
        match album_ref {
            Ok(c) => {
                debug!("Album {} has ID {}", c.name, c.id);
                upload_album_id = c.id.clone();
                upload_album_owner_id = c.owner_id.clone();
            }
            Err(e) => {
                debug!("Err {:?}", e);
                return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)));
            }
        };
    }

    // Create an upload logger and read it for prior uploads
    let default_path = Path::new("/tmp/uploader_amazon_photos.log");
    let catalog_file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(default_path)
        .unwrap();
    let mut catalog: HashMap<String, String> = HashMap::new();
    let reader = BufReader::new(catalog_file);
    for line in reader.lines() {
        let line = line.unwrap();
        let elements: Vec<&str> = line.split(';').collect();
        catalog.insert(elements[0].to_string(), elements[1].to_string());
    }
    let catalog_file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(default_path)
        .unwrap();
    let catalog_writer: BufWriter<File> = BufWriter::new(catalog_file);

    info!("Uploading pictures...");

    // Validate and collect entries from all input paths
    if args.input.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "At least one --input path must be specified",
        ));
    }

    let mut entries: Vec<walkdir::DirEntry> = Vec::new();

    for input_path in &args.input {
        // Expand tilde in path
        let expanded_path = if input_path.starts_with("~") {
            if let Some(home) = dirs::home_dir() {
                home.join(input_path.strip_prefix("~/").unwrap_or(&input_path[2..]))
            } else {
                Path::new(input_path).to_path_buf()
            }
        } else {
            Path::new(input_path).to_path_buf()
        };
        let path = expanded_path.as_path();

        if !path.exists() {
            error!("Path does not exist: {}", input_path);
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Path not found: {}", input_path),
            ));
        }

        if path.is_file() {
            // Single file - check if it's a supported image format
            let is_supported = path.extension().is_some_and(|e| {
                let ext = e.to_string_lossy().to_lowercase();
                ext == "jpg" || ext == "jpeg" || ext == "png"
            });

            if is_supported {
                // Create a synthetic DirEntry for the file
                // We need to walk the parent directory and filter for this specific file
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                let file_name = path.file_name().unwrap();

                for entry in WalkDir::new(parent).max_depth(1).into_iter().filter_map(Result::ok) {
                    if entry.file_name() == file_name {
                        entries.push(entry);
                        break;
                    }
                }
            } else {
                error!("File is not a supported image format (jpg/png): {}", input_path);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("File is not a supported image format (jpg/png): {}", input_path),
                ));
            }
        } else if path.is_dir() {
            // Directory - walk and collect all supported image files
            let dir_entries: Vec<_> = WalkDir::new(path)
                .into_iter()
                .filter(|s| {
                    s.as_ref().is_ok_and(|si| {
                        si.path().extension().is_some_and(|e| {
                            let ext = e.to_string_lossy().to_lowercase();
                            ext == "jpg" || ext == "jpeg" || ext == "png"
                        })
                    })
                })
                .filter_map(Result::ok)
                .collect();

            entries.extend(dir_entries);
        }
    }

    if entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No supported image files (jpg/png) found in the specified input path(s)",
        ));
    }
    let progress_bar = ProgressBar::new(entries.len() as u64);
    progress_bar
        .set_style(ProgressStyle::with_template("{bar} {pos:>7}/{len:7} {eta_precise}").unwrap());

    // Prepare files for upload with deduplication
    let mut files_to_upload = Vec::new();
    for entry in entries {
        let path = entry.path().to_path_buf();

        // Check for prior processing
        let attr = match fs::metadata(&path) {
            Ok(v) => v,
            Err(e) => {
                error!("Cannot open {} ({}), skipping ", path.to_string_lossy(), e.kind());
                progress_bar.inc(1);
                continue;
            }
        };
        let mut contents_vec: Vec<u8> = Vec::with_capacity(attr.len() as usize);
        // Now get contents
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                error!("Cannot open {} ({}), skipping ", path.to_string_lossy(), e.kind());
                progress_bar.inc(1);
                continue;
            }
        };
        let _ = file.read_to_end(&mut contents_vec);
        // Finally, get hash
        let md5sum = md5::compute(&contents_vec);
        let md5sum_str = format!("{:x}", md5sum);
        if catalog.contains_key(&md5sum_str) {
            uploaded_ids.push(format!(
                "{}:{}",
                upload_album_owner_id,
                catalog.get(&md5sum_str).unwrap()
            ));
            progress_bar.inc(1);
            continue;
        }

        files_to_upload.push((path, contents_vec, md5sum_str));
    }

    // Upload files concurrently with a semaphore to limit parallelism
    const MAX_CONCURRENT_UPLOADS: usize = 6;
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS));
    let uploader = Arc::new(Mutex::new(uploader));
    let catalog_writer = Arc::new(Mutex::new(catalog_writer));
    let uploaded_ids = Arc::new(Mutex::new(uploaded_ids));
    let catalog = Arc::new(Mutex::new(catalog));
    let progress_bar = Arc::new(progress_bar);
    let upload_album_owner_id = Arc::new(upload_album_owner_id);

    stream::iter(files_to_upload)
        .for_each_concurrent(MAX_CONCURRENT_UPLOADS, |(path, contents_vec, md5sum_str)| {
            let semaphore = semaphore.clone();
            let uploader = uploader.clone();
            let catalog_writer = catalog_writer.clone();
            let uploaded_ids = uploaded_ids.clone();
            let catalog = catalog.clone();
            let progress_bar = progress_bar.clone();
            let upload_album_owner_id = upload_album_owner_id.clone();

            async move {
                let _permit = semaphore.acquire().await.unwrap();

                debug!("Uploading {}", path.as_os_str().to_str().unwrap());
                let upload_data = {
                    let mut uploader = uploader.lock().await;
                    uploader.upload_picture(&path, Some(&contents_vec), Some(&md5sum_str)).await
                };

                match upload_data {
                    Ok(val) => {
                        debug!("Upload OK");
                        let id_str = format!("{}:{}", *upload_album_owner_id, val);
                        uploaded_ids.lock().await.push(id_str);

                        let log_line = format!("{};{}\n", md5sum_str, val);
                        let _ = catalog_writer.lock().await.write(log_line.as_bytes());
                        catalog.lock().await.insert(md5sum_str, val);
                    }
                    Err(conn_err) => {
                        error!("Photo not uploaded ({}), skipped", conn_err);
                    }
                }
                progress_bar.inc(1);
            }
        })
        .await;

    progress_bar.finish_with_message("Done!");

    // Unwrap Arc wrappers
    let uploaded_ids = Arc::try_unwrap(uploaded_ids).unwrap().into_inner();
    let uploader = Arc::try_unwrap(uploader).unwrap().into_inner();
    let mut catalog_writer = Arc::try_unwrap(catalog_writer).unwrap().into_inner();

    // debug!("Uploaded {:?}", uploaded_ids);

    if !is_albumless {
        // Can't add more than 25 items at a single time
        let max_chunk_size = 25;
        let ids_chunks_count = match uploaded_ids.len() % max_chunk_size != 0 {
            true => ((uploaded_ids.len() - (uploaded_ids.len() % max_chunk_size)) / max_chunk_size) + 1,
            false => uploaded_ids.len() / max_chunk_size,
        };
        info!("Adding uploaded pictures into the album...");
        let progress_bar = ProgressBar::new(ids_chunks_count as u64);
        progress_bar
            .set_style(ProgressStyle::with_template("{bar} {pos:>7}/{len:7} {eta_precise}").unwrap());
        for ids_batch in uploaded_ids.chunks(max_chunk_size) {
            let album_add_operation = uploader
                .add_to_album(upload_album_id.clone(), ids_batch)
                .await;
            match album_add_operation {
                Ok(_) => progress_bar.inc(1),
                Err(conn_err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("{:?}", conn_err),
                    ));
                }
            };
        }
        progress_bar.finish();
        info!("Done!");
    }

    let _ = catalog_writer.flush();

    Ok(())
}
