use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::Error;

// TODO(#175): Use manifest parsing in BB instead of hardcoding these
const G1_START: usize = 28;
const G2_START: usize = 28 + (5_040_001 * 64);
const G2_END: usize = G2_START + 128 - 1;

// TODO(#162): Allow downloading from more than just the first transcript
const TRANSCRIPT_URL: &str =
    "http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat";

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct CRS {
    pub(crate) g1_data: Vec<u8>,
    pub(crate) g2_data: Vec<u8>,
    pub(crate) num_points: usize,
}

impl CRS {
    pub(crate) async fn update(&mut self, num_points: usize) -> Result<(), Error> {
        // We already have some data, so start at the end of our list
        let g1_start = self.g1_data.len();
        // UltraPlonk requires a CRS equal to circuit size plus one!
        // We need to bump our polynomial degrees by 1 to handle zero knowledge
        let g1_end = G1_START + ((num_points + 1) * 64) - 1;

        // TODO(blaine): Make sure g1_start isn't off-by-one
        let g1_data = download(g1_start, g1_end).await?;

        self.g1_data = g1_data;
        self.num_points = num_points;

        Ok(())
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

impl From<&CRS> for Vec<u8> {
    fn from(value: &CRS) -> Self {
        bincode::serialize(value).unwrap()
    }
}

async fn download(start: usize, end: usize) -> Result<Vec<u8>, Error> {
    use bytes::{BufMut, BytesMut};
    use futures_util::StreamExt;

    let client = Client::new();

    let request = client
        .get(TRANSCRIPT_URL)
        .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
        .build()
        .map_err(|source| Error::CRSRequest {
            url: TRANSCRIPT_URL.to_string(),
            source,
        })?;
    let response = client
        .execute(request)
        .await
        .map_err(|source| Error::CRSFetch {
            url: TRANSCRIPT_URL.to_string(),
            source,
        })?;
    let total_size = response.content_length().ok_or(Error::CRSLength {
        url: TRANSCRIPT_URL.to_string(),
    })?;

    // Indicatif setup
    use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
    let pb = ProgressBar::new(total_size).with_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes:>7}/{total_bytes:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    // download chunks
    let mut crs_bytes = BytesMut::default();
    let mut stream = response.bytes_stream();

    println!(
        "\nDownloading the Ignite SRS ({})\n",
        HumanBytes(total_size)
    );
    while let Some(item) = stream.next().await {
        let mut chunk = item.map_err(|source| Error::CRSDownload { source })?;
        crs_bytes.put(&mut chunk);
        pb.inc(chunk.len() as u64);
    }
    pb.finish_with_message("Downloaded the SRS successfully!\n");

    Ok(crs_bytes.into())
}

pub(crate) async fn download_crs(num_points: usize) -> Result<CRS, Error> {
    // UltraPlonk requires a CRS equal to circuit size plus one!
    // We need to bump our polynomial degrees by 1 to handle zero knowledge
    let g1_end = G1_START + ((num_points + 1) * 64) - 1;

    let g1_data = download(G1_START, g1_end).await?;
    let g2_data = download(G2_START, G2_END).await?;

    Ok(CRS {
        g1_data,
        g2_data,
        num_points,
    })
}

#[cfg(feature = "native")]
#[test]
fn does_not_panic() -> Result<(), Error> {
    use tokio::runtime::Builder;

    let num_points = 4 * 1024;

    let crs = Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(download_crs(num_points))?;

    let p_points = barretenberg_sys::pippenger::new(&crs.g1_data);

    unsafe {
        Vec::from_raw_parts(p_points as *mut u8, num_points * 32, num_points * 32);
    }
    //TODO check that p_points memory is properly free

    Ok(())
}
