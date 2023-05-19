use bytesize::ByteSize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

use crate::{CRSError, Error};

// TODO(#175): Use manifest parsing in BB instead of hardcoding these
const G1_START: usize = 28;
const G2_START: usize = 28 + (5_040_001 * 64);
const G2_END: usize = G2_START + 128 - 1;

const TRANSCRIPT_URL_ENV_VAR: &str = "TRANSCRIPT_URL";
const TRANSCRIPT_URL_FALLBACK: &str =
    "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat";

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct CRS {
    pub(crate) g1_data: Vec<u8>,
    pub(crate) g2_data: Vec<u8>,
    pub(crate) num_points: usize,
}

impl CRS {
    pub(crate) async fn update(&mut self, num_points: usize) -> Result<(), Error> {
        // We already have some data, so start at the end of our list
        let g1_start = G1_START + self.g1_data.len();
        // UltraPlonk requires a CRS equal to circuit size plus one!
        // We need to bump our polynomial degrees by 1 to handle zero knowledge
        let g1_end = G1_START + ((num_points + 1) * 64) - 1;

        // If the `g1_end` is <= the `g1_start`, we already have enough CRS
        if g1_end > g1_start {
            let mut g1_data = download(g1_start, g1_end).await?;

            self.g1_data.append(&mut g1_data);
            self.num_points = num_points;
        }

        Ok(())
    }
}

impl TryFrom<&[u8]> for CRS {
    type Error = CRSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(value).map_err(|source| CRSError::Deserialize { source })
    }
}

impl TryFrom<Vec<u8>> for CRS {
    type Error = CRSError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::deserialize(&value).map_err(|source| CRSError::Deserialize { source })
    }
}

impl TryFrom<CRS> for Vec<u8> {
    type Error = CRSError;

    fn try_from(value: CRS) -> Result<Self, Self::Error> {
        bincode::serialize(&value).map_err(|source| CRSError::Serialize { source })
    }
}

impl TryFrom<&CRS> for Vec<u8> {
    type Error = CRSError;

    fn try_from(value: &CRS) -> Result<Self, Self::Error> {
        bincode::serialize(value).map_err(|source| CRSError::Serialize { source })
    }
}

async fn download(start: usize, end: usize) -> Result<Vec<u8>, CRSError> {
    // TODO(#187): Allow downloading from more than just the first transcript
    // We try to load a URL from the environment and otherwise fallback to a hardcoded URL to allow
    // Nix to override the URL for testing in the sandbox, where there is no network access on Linux
    let transcript_url = match env::var(TRANSCRIPT_URL_ENV_VAR) {
        Ok(url) => url,
        Err(_) => TRANSCRIPT_URL_FALLBACK.into(),
    };

    let client = Client::new();

    let request = client
        .get(&transcript_url)
        .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
        .build()
        .map_err(|source| CRSError::Request {
            url: transcript_url.to_string(),
            source,
        })?;
    let response = client
        .execute(request)
        .await
        .map_err(|source| CRSError::Fetch {
            url: transcript_url.to_string(),
            source,
        })?;
    let total_size = response.content_length().ok_or(CRSError::Length {
        url: transcript_url.to_string(),
    })?;

    // TODO(#195): We probably want to consider an injectable logger so we can have logging in JS
    println!(
        "\nDownloading the Ignite SRS ({})",
        ByteSize(total_size).to_string_as(false)
    );
    let crs_bytes = response
        .bytes()
        .await
        .map_err(|source| CRSError::Download { source })?;
    println!("Downloaded the SRS successfully!");

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

#[cfg(test)]
mod tests {
    use tokio::test;

    use crate::{crs::download_crs, Error};

    #[test]
    async fn does_not_panic() -> Result<(), Error> {
        use crate::Barretenberg;

        let backend = Barretenberg::default();
        let num_points = 4 * 1024;

        let crs = download_crs(num_points).await?;

        let _pippenger = backend.get_pippenger(&crs.g1_data)?;

        // TODO(#193) check that p_points memory is properly free

        Ok(())
    }

    #[test]
    async fn crs_update() -> Result<(), Error> {
        let partial_num_points = 2;
        let full_num_points = 12;

        // Create a partial CRS
        let mut partial_crs = download_crs(partial_num_points).await?;

        // Update the partial CRS to the full number of points
        partial_crs.update(full_num_points).await?;

        // Fetch a full CRS to compare
        let full_crs = download_crs(full_num_points).await?;

        assert_eq!(partial_crs, full_crs);
        Ok(())
    }
}
