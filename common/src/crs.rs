// TODO(blaine): Use manifest parsing in BB instead of hardcoding these
const G1_START: usize = 28;
const G2_START: usize = 28 + (5_040_001 * 64);
const G2_END: usize = G2_START + 128 - 1;

// XXX: Below is the logic to download the CRS if it is not already present
#[cfg(feature = "std")]
pub mod download {
    use std::{env, path::PathBuf};

    const BACKEND_IDENTIFIER: &str = "acvm-backend-barretenberg";
    const TRANSCRIPT_NAME: &str = "transcript00.dat";

    pub fn transcript_location() -> PathBuf {
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

    pub fn read_crs(path: PathBuf) -> Vec<u8> {
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

    pub fn download_crs(mut path_to_transcript: PathBuf) {
        // Remove old crs
        if path_to_transcript.exists() {
            let _ = std::fs::remove_file(path_to_transcript.as_path());
        }
        // Pop off the transcript component to get just the directory
        path_to_transcript.pop();

        if !path_to_transcript.exists() {
            std::fs::create_dir_all(&path_to_transcript).unwrap();
        }

        let url =
            "http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat";
        use downloader::Downloader;
        let mut downloader = Downloader::builder()
            .download_folder(path_to_transcript.as_path())
            .build()
            .unwrap();

        let dl = downloader::Download::new(url);
        let dl = dl.file_name(&PathBuf::from(TRANSCRIPT_NAME));
        let dl = dl.progress(SimpleReporter::create());
        let result = downloader.download(&[dl]).unwrap();

        for r in result {
            match r {
                Err(e) => println!("Error: {e}"),
                Ok(s) => println!("\nSRS is located at : {:?}", &s.file_name),
            };
        }
    }
    // Taken from https://github.com/hunger/downloader/blob/main/examples/download.rs
    struct SimpleReporterPrivate {
        started: std::time::Instant,
        progress_bar: indicatif::ProgressBar,
    }
    struct SimpleReporter {
        private: std::sync::Mutex<Option<SimpleReporterPrivate>>,
    }

    impl SimpleReporter {
        fn create() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                private: std::sync::Mutex::new(None),
            })
        }
    }

    impl downloader::progress::Reporter for SimpleReporter {
        fn setup(&self, max_progress: Option<u64>, _message: &str) {
            let bar = indicatif::ProgressBar::new(max_progress.unwrap());
            bar.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                    .progress_chars("##-"),
            );

            let private = SimpleReporterPrivate {
                started: std::time::Instant::now(),
                progress_bar: bar,
            };
            println!("\nDownloading the Ignite SRS (340MB)\n");

            let mut guard = self.private.lock().unwrap();
            *guard = Some(private);
        }

        fn progress(&self, current: u64) {
            if let Some(p) = self.private.lock().unwrap().as_mut() {
                p.progress_bar.set_position(current);
            }
        }

        fn set_message(&self, _message: &str) {}

        fn done(&self) {
            let mut guard = self.private.lock().unwrap();
            let p = guard.as_mut().unwrap();
            p.progress_bar.finish();
            println!("Downloaded the SRS successfully!");
            println!(
                "Time Elapsed: {}",
                indicatif::HumanDuration(p.started.elapsed())
            );
        }
    }
}

#[cfg(feature = "js")]
pub mod download {
    use std::{env, path::PathBuf};

    pub fn download_crs(mut path_to_transcript: PathBuf) {
        println!("Unable to download in JS");
    }

    pub fn read_crs(path: PathBuf) -> Vec<u8> {
        // include_bytes!("/Users/phated/.nargo/backends/acvm-backend-barretenberg/transcript00.dat")
        //     .to_vec()
        vec![]
    }

    pub fn transcript_location() -> PathBuf {
        PathBuf::from("/Users/phated/.nargo/backends/acvm-backend-barretenberg/transcript00.dat")
    }
}

#[allow(clippy::upper_case_acronyms)]
pub struct CRS {
    pub g1_data: Vec<u8>,
    pub g2_data: Vec<u8>,
    pub num_points: usize,
}

impl CRS {
    pub fn new(num_points: usize) -> CRS {
        // UltraPlonk requires a CRS equal to circuit size plus one!
        // We need to bump our polynomial degrees by 1 to handle zero knowledge
        let g1_end = G1_START + ((num_points + 1) * 64) - 1;

        // If the CRS does not exist, then download it from S3
        // if !download::transcript_location().exists() {
        //     download::download_crs(download::transcript_location());
        // }

        // Read CRS, if it's incomplete, download it
        let mut crs = download::read_crs(download::transcript_location());
        // if crs.len() < G2_END + 1 {
        //     download::download_crs(download::transcript_location());
        //     crs = download::read_crs(download::transcript_location());
        // }

        let g1_data = crs[G1_START..=g1_end].to_vec();
        let g2_data = crs[G2_START..=G2_END].to_vec();

        CRS {
            g1_data,
            g2_data,
            num_points,
        }
    }
}

// TODO(blaine): Come up with a better abstraction for the CRS so we don't need to read the
// file everytime we need the G2
pub struct G2 {
    pub data: Vec<u8>,
}

impl G2 {
    pub fn new() -> G2 {
        // If the CRS does not exist, then download it from S3
        if !download::transcript_location().exists() {
            download::download_crs(download::transcript_location());
        }

        // Read CRS, if it's incomplete, download it
        let mut crs = download::read_crs(download::transcript_location());
        if crs.len() < G2_END + 1 {
            download::download_crs(download::transcript_location());
            crs = download::read_crs(download::transcript_location());
        }

        let data = crs[G2_START..=G2_END].to_vec();

        G2 { data }
    }
}

impl Default for G2 {
    fn default() -> Self {
        Self::new()
    }
}

// #[test]
// fn does_not_panic() {
//     let num_points = 4 * 1024;

//     let crs = CRS::new(num_points);

//     let p_points = barretenberg_sys::pippenger::new(&crs.g1_data);

//     unsafe {
//         Vec::from_raw_parts(
//             p_points as *mut u8,
//             num_points * 32 as usize,
//             num_points * 32 as usize,
//         );
//     }
//     //TODO check that p_points memory is properly free
// }
// #[test]
// #[ignore]
// fn downloading() {
//     use tempfile::tempdir;
//     let dir = tempdir().unwrap();

//     let file_path = dir.path().to_path_buf().join("transcript00.dat");
//     download_crs(file_path);
// }
