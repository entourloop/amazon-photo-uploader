mod amzn_photo;
mod config;

use amzn_photo::AmznPhoto;
use config::Config;

use clap::Parser;
use env_logger::{Builder, Target};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Write}, path::Path,
};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The global album name to use for the upload
    #[arg(long)]
    album_name: Option<String>,

    /// The input directory to process
    #[arg(long)]
    input: String,

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
    let mut uploader = AmznPhoto::new(&mut conf, args.dry_run);
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
    let mut catalog_writer: BufWriter<File> = BufWriter::new(catalog_file);

    info!("Uploading pictures...");
    let entries: Vec<_> = WalkDir::new(&args.input)
        .into_iter()
        .filter(|s| {
            s.as_ref().is_ok_and(|si| {
                si.path()
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("jpg"))
            })
        })
        .collect();
    let progress_bar = ProgressBar::new(entries.len() as u64);
    progress_bar
        .set_style(ProgressStyle::with_template("{bar} {pos:>7}/{len:7} {eta_precise}").unwrap());

    for entry in entries {
        let dir_entry = entry.unwrap();
        let path = dir_entry.path();

        // Check for prior processing
        let attr = match fs::metadata(path) {
            Ok(v) => v,
            Err(e) => {
                error!("Cannot open {} ({}), skipping ", path.to_string_lossy(), e.kind());
                progress_bar.inc(1);
                continue;
            }
        };
        let mut contents_vec: Vec<u8> = Vec::with_capacity(attr.len() as usize);
        // Now get contents
        let mut file = File::open(path).unwrap();
        let _ = file.read_to_end(&mut contents_vec);
        // Finally, get hash
        let md5sum = md5::compute(&contents_vec);
        let md5sum_str = format!("{:x}", md5sum);
        if catalog.contains_key(&md5sum_str) {
            // debug!(
            //     "Skipping already processed entry {}",
            //     path.to_str().unwrap()
            // );
            uploaded_ids.push(format!(
                "{}:{}",
                upload_album_owner_id,
                catalog.get(&md5sum_str).unwrap()
            ));
            progress_bar.inc(1);
            continue;
        }

        debug!("Uploading {}", path.as_os_str().to_str().unwrap());
        let upload_data = uploader.upload_picture(path).await;
        match upload_data {
            Ok(val) => {
                debug!("Upload OK");
                uploaded_ids.push(format!("{}:{}", upload_album_owner_id, val));
                let _ = catalog_writer.write(format!("{};{}\n", md5sum_str, val).as_bytes());
                catalog.insert(md5sum_str, val);
            }
            Err(conn_err) => {
                error!("Photo not uploaded ({}), skipped", conn_err);
            }
        }
        progress_bar.inc(1);
    }
    progress_bar.finish_with_message("Done!");
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
