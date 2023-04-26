use std::{env, fs::File, io::Write, path::PathBuf};

use serde::{Deserialize, Serialize};

use futures_util::StreamExt;

// TODO(blaine): Use manifest parsing in BB instead of hardcoding these
const G1_START: usize = 28;
const G2_START: usize = 28 + (5_040_001 * 64);
const G2_END: usize = G2_START + 128 - 1;

const BACKEND_IDENTIFIER: &str = "acvm-backend-barretenberg";
const TRANSCRIPT_NAME: &str = "transcript00.dat";
const TRANSCRIPT_URL: &str =
    "http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat";

fn transcript_location() -> PathBuf {
    match env::var("BARRETENBERG_TRANSCRIPT") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => dirs::home_dir()
            .unwrap()
            .join(".nargo")
            .join("backends")
            .join(BACKEND_IDENTIFIER)
            .join(TRANSCRIPT_NAME),
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct CRS {
    pub(crate) g1_data: Vec<u8>,
    pub(crate) g2_data: Vec<u8>,
    pub(crate) num_points: usize,
}

impl CRS {
    pub(crate) fn new(num_points: usize) -> CRS {
        // UltraPlonk requires a CRS equal to circuit size plus one!
        // We need to bump our polynomial degrees by 1 to handle zero knowledge
        let g1_end = G1_START + ((num_points + 1) * 64) - 1;

        // If the CRS does not exist, then download it from S3
        if !transcript_location().exists() {
            download_crs(transcript_location()).unwrap();
        }

        // Read CRS, if it's incomplete, download it
        let mut crs = read_crs(transcript_location());
        if crs.len() < G2_END + 1 {
            download_crs(transcript_location()).unwrap();
            crs = read_crs(transcript_location());
        }

        let g1_data = crs[G1_START..=g1_end].to_vec();
        let g2_data = crs[G2_START..=G2_END].to_vec();

        CRS {
            g1_data,
            g2_data,
            num_points,
        }
    }
}

impl From<&[u8]> for CRS {
    fn from(value: &[u8]) -> Self {
        bincode::deserialize(value).unwrap()
    }
}

impl From<Vec<u8>> for CRS {
    fn from(value: Vec<u8>) -> Self {
        bincode::deserialize(&value).unwrap()
    }
}

impl From<CRS> for Vec<u8> {
    fn from(value: CRS) -> Self {
        bincode::serialize(&value).unwrap()
    }
}

fn read_crs(path: PathBuf) -> Vec<u8> {
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            assert!(
                e.kind() != std::io::ErrorKind::PermissionDenied,
                "please run again with appropriate permissions."
            );
            panic!(
                "Could not find transcript at location {}.\n Starting Download",
                path.display()
            );
        }
    }
}

// XXX: Below is the logic to download the CRS if it is not already present

pub(crate) fn download_crs(path_to_transcript: PathBuf) -> Result<(), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(download_crs_async(path_to_transcript))
}

async fn download_crs_async(path_to_transcript: PathBuf) -> Result<(), String> {
    // Remove old crs
    if path_to_transcript.exists() {
        let _ = std::fs::remove_file(path_to_transcript.as_path());
    }

    // Pop off the transcript component to get just the directory
    let transcript_dir = path_to_transcript
        .parent()
        .expect("transcript file should have parent");

    if !transcript_dir.exists() {
        std::fs::create_dir_all(transcript_dir).unwrap();
    }

    let res = reqwest::get(TRANSCRIPT_URL)
        .await
        .map_err(|err| format!("Failed to GET from '{}' ({})", TRANSCRIPT_URL, err))?;
    let total_size = res.content_length().ok_or(format!(
        "Failed to get content length from '{}'",
        TRANSCRIPT_URL
    ))?;

    // Indicatif setup
    use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
    let pb = ProgressBar::new(total_size).with_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes:>7}/{total_bytes:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    // download chunks
    let mut file = File::create(path_to_transcript.clone()).map_err(|err| {
        format!(
            "Failed to create file '{}' ({})",
            path_to_transcript.display(),
            err
        )
    })?;
    let mut stream = res.bytes_stream();

    println!(
        "\nDownloading the Ignite SRS ({})\n",
        HumanBytes(total_size)
    );
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|_| "Error while downloading file".to_string())?;
        file.write_all(&chunk)
            .map_err(|_| "Error while writing to file".to_string())?;
        pb.inc(chunk.len() as u64);
    }
    pb.finish_with_message("Downloaded the SRS successfully!\n");

    println!("SRS is located at: {:?}", &path_to_transcript);

    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn does_not_panic() {
    let num_points = 4 * 1024;

    let crs = CRS::new(num_points);

    let p_points = barretenberg_sys::pippenger::new(&crs.g1_data);

    unsafe {
        Vec::from_raw_parts(p_points as *mut u8, num_points * 32, num_points * 32);
    }
    //TODO check that p_points memory is properly free
}
#[test]
#[ignore]
fn downloading() {
    use tempfile::tempdir;
    let dir = tempdir().unwrap();

    let file_path = dir.path().to_path_buf().join("transcript00.dat");
    let res = download_crs(file_path);
    assert_eq!(res, Ok(()));
}
