pub(crate) use common::crs::CRS;

#[test]
fn does_not_panic() {
    let num_points = 4 * 1024;

    let crs = CRS::new(num_points);

    let p_points = barretenberg_wrapper::pippenger::new(&crs.g1_data);

    unsafe {
        Vec::from_raw_parts(p_points as *mut u8, num_points * 32, num_points * 32);
    }
    //TODO check that p_points memory is properly free
}
#[test]
#[ignore]
fn downloading() {
    use common::crs::download_crs;

    use tempfile::tempdir;
    let dir = tempdir().unwrap();

    let file_path = dir.path().to_path_buf().join("transcript00.dat");
    download_crs(file_path);
}
