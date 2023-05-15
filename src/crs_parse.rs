use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

const TRANSCRIPT_FILES: [&str; 1] = ["transcript00.dat"];

#[derive(Debug, Clone, Copy)]
pub(crate) struct SerializedFq([u64; 4]);

impl SerializedFq {
    /// Returns the number of bytes needed to encode a
    /// Fq field element in bytes
    pub(crate) fn size_in_bytes() -> u64 {
        32
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SerializedG1Affine {
    x: SerializedFq,
    y: SerializedFq,
}

impl SerializedG1Affine {
    /// Returns the number of bytes needed to encode a
    /// a G1 affine point.
    pub(crate) fn size_in_bytes() -> u64 {
        SerializedFq::size_in_bytes() * 2
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SerializedFq2 {
    c0: SerializedFq,
    c1: SerializedFq,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SerializedG2Affine {
    x: SerializedFq2,
    y: SerializedFq2,
}

pub(crate) struct CRS {
    pub g1_points: Vec<SerializedG1Affine>,
    pub g2_point: SerializedG2Affine,
}

#[derive(Debug)]
struct Manifest {
    transcript_number: u32,
    total_transcripts: u32,
    total_g1_points: u32,
    total_g2_points: u32,
    num_g1_points: u32,
    num_g2_points: u32,
    start_from: u32,
}

#[derive(Debug)]
pub enum CRSError {
    IO(std::io::Error),
    NotEnoughPoints { need: u32 },
}

impl Manifest {
    /// Returns the number of bytes needed to encode the `Manifest`
    fn size() -> u64 {
        let num_fields_in_struct = 7;
        let size_of_each_field_in_bytes = 32 / 8;

        num_fields_in_struct * size_of_each_field_in_bytes
    }
    /// Reads `Manifest` from the given `Reader`
    fn read(reader: &mut impl Read) -> std::io::Result<Manifest> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let transcript_number = u32::from_be_bytes(bytes);

        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let total_transcripts = u32::from_be_bytes(bytes);

        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let total_g1_points = u32::from_be_bytes(bytes);

        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let total_g2_points = u32::from_be_bytes(bytes);

        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let num_g1_points = u32::from_be_bytes(bytes);

        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let num_g2_points = u32::from_be_bytes(bytes);

        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        let start_from = u32::from_be_bytes(bytes);

        Ok(Manifest {
            transcript_number,
            total_transcripts,
            total_g1_points,
            total_g2_points,
            num_g1_points,
            num_g2_points,
            start_from,
        })
    }
}

impl CRS {
    pub(crate) fn parse_g1_points<P: AsRef<Path>>(
        path_to_transcript: P,
        num_points: u32,
    ) -> std::io::Result<(Vec<SerializedG1Affine>, u32)> {
        let file_to_transcript = File::open(&path_to_transcript)?;
        let mut reader = BufReader::new(&file_to_transcript);
        let manifest = Manifest::read(&mut reader)?;
        let g1_points = CRS::read_serialized_g1_points(&mut reader, num_points);

        let remaining_points = if manifest.num_g1_points < num_points {
            num_points - manifest.num_g1_points
        } else {
            manifest.num_g1_points - num_points
        };

        return Ok((g1_points, remaining_points));
    }

    pub(crate) fn parse_g2_point<P: AsRef<Path>>(
        path_to_first_transcript: P,
    ) -> std::io::Result<SerializedG2Affine> {
        let mut file_to_transcript = File::open(&path_to_first_transcript)?;
        let mut reader = BufReader::new(&file_to_transcript);
        let manifest = Manifest::read(&mut reader)?;

        use std::io::{Seek, SeekFrom};

        let g2_offset = SerializedG1Affine::size_in_bytes() * manifest.num_g1_points as u64;
        file_to_transcript.seek(SeekFrom::Start(g2_offset + Manifest::size()))?;
        let mut reader = BufReader::new(file_to_transcript);
        Ok(CRS::read_serialized_g2_point(&mut reader))
    }

    /// Reads `degree` number of points from the file at `path`
    /// and stores those points in the CRS.
    ///
    /// If the `degree` is too much, then a `NotEnoughPoints` error is returned.
    pub(crate) fn from_raw_dir<P: AsRef<Path>>(path: P, degree: u32) -> Result<CRS, CRSError> {
        let path_to_transcript00 = path.as_ref().join(TRANSCRIPT_FILES[0]);
        let (g1_points, remaining) =
            Self::parse_g1_points(&path_to_transcript00, degree).map_err(CRSError::IO)?;

        let g2_point = Self::parse_g2_point(path_to_transcript00).map_err(CRSError::IO)?;

        Ok(CRS {
            g1_points,
            g2_point,
        })
    }

    /// Reads `degree` number of G1 Points from the transcript
    fn read_serialized_g1_points(reader: &mut impl Read, degree: u32) -> Vec<SerializedG1Affine> {
        let mut g1_points = Vec::with_capacity(degree as usize);

        for _ in 0..degree {
            let x_limbs = read_limbs(reader);
            let y_limbs = read_limbs(reader);

            let point = SerializedG1Affine {
                x: SerializedFq(x_limbs),
                y: SerializedFq(y_limbs),
            };
            g1_points.push(point);
        }
        g1_points
    }

    fn read_serialized_g2_point(reader: &mut impl Read) -> SerializedG2Affine {
        let x_c0_limbs = read_limbs(reader);
        let x_c1_limbs = read_limbs(reader);

        let y_c0_limbs = read_limbs(reader);
        let y_c1_limbs = read_limbs(reader);

        let x = SerializedFq2 {
            c0: SerializedFq(x_c0_limbs),
            c1: SerializedFq(x_c1_limbs),
        };
        let y = SerializedFq2 {
            c0: SerializedFq(y_c0_limbs),
            c1: SerializedFq(y_c1_limbs),
        };
        SerializedG2Affine { x, y }
    }
}

// Read four u64s into a slice from a reader
// limbs are not in montgomery form
fn read_limbs(reader: &mut impl Read) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for limb in limbs.iter_mut() {
        let mut bytes = [0u8; 8];
        reader.read_exact(&mut bytes).unwrap();
        *limb = u64::from_be_bytes(bytes);
    }
    limbs
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use ark_ff::{BigInteger256, PrimeField};

    use crate::crs::download_crs;

    use super::{SerializedG1Affine, SerializedG2Affine, CRS};

    // Convert the limbs into montgomery form
    // and then a field element
    fn limbs_to_field_element(limbs: [u64; 4]) -> Fq {
        Fq::from_repr(BigInteger256::new(limbs)).unwrap()
    }

    struct ArkCRS {
        g1_points: Vec<G1Affine>,
        g2_point: G2Affine,
    }

    impl ArkCRS {
        fn from_raw_crs(crs: CRS) -> Self {
            Self {
                g1_points: to_arkworks_points_g1(&crs.g1_points),
                g2_point: to_arkworks_point_g2(crs.g2_point),
            }
        }
    }

    fn to_arkworks_points_g1(points: &[SerializedG1Affine]) -> Vec<G1Affine> {
        let mut ark_points = Vec::new();

        for point in points {
            let ark_x = limbs_to_field_element(point.x.0);
            let ark_y = limbs_to_field_element(point.y.0);
            ark_points.push(G1Affine::new(ark_x, ark_y, false))
        }
        ark_points
    }
    fn to_arkworks_point_g2(point: SerializedG2Affine) -> G2Affine {
        let ark_x_c0 = limbs_to_field_element(point.x.c0.0);
        let ark_x_c1 = limbs_to_field_element(point.x.c1.0);
        let x = Fq2::new(ark_x_c0, ark_x_c1);

        let ark_y_c0 = limbs_to_field_element(point.y.c0.0);
        let ark_y_c1 = limbs_to_field_element(point.y.c1.0);
        let y = Fq2::new(ark_y_c0, ark_y_c1);

        G2Affine::new(x, y, false)
    }
    #[test]
    fn read_crs() {
        use ark_bn254::Bn254;
        use ark_ec::AffineCurve;
        use ark_ec::PairingEngine;
        use ark_ff::One;

        use tempfile::tempdir;
        let dir = tempdir().unwrap();

        let dir_path = dir.path().to_path_buf();
        let file_path = dir_path.join("transcript00.dat");
        let res = download_crs(file_path, 0);
        assert!(res.is_ok());

        let crs = CRS::from_raw_dir(dir_path, 1_000).unwrap();
        let crs = ArkCRS::from_raw_crs(crs);
        for point in &crs.g1_points {
            assert!(point.is_on_curve());
            assert!(point.is_in_correct_subgroup_assuming_on_curve())
        }
        let ark_g2 = crs.g2_point;
        assert!(ark_g2.is_on_curve());
        assert!(ark_g2.is_in_correct_subgroup_assuming_on_curve());

        let p0 = -crs.g1_points[1]; // -xG
        let p1 = crs.g1_points[0]; // G
        let q0 = G2Affine::prime_subgroup_generator(); // Q
        let q1 = crs.g2_point; // xQ

        // e(-xG, Q) * e(G, xQ)
        // e(-xG, Q) * e(xG, Q)
        // e( xG - xG, Q)
        // e(0*G, Q)
        // = 1
        let res1 = Bn254::pairing(p0, q0);
        let res2 = Bn254::pairing(p1, q1);
        let res = res1 * res2;
        assert!(res.is_one());

        let res = Bn254::product_of_pairings(&vec![(p0.into(), q0.into()), (p1.into(), q1.into())]);
        assert!(res.is_one());
    }
}
