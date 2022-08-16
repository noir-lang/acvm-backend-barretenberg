// We need a grumpkin module here to ensure that the rust version of grumpkin is interopable
// with the C++ version of grumpkin.
//
// The most notable difference is the serialisation strategy that the C++
// code uses, which is non-standard.

use ark_ec::{AffineCurve, ProjectiveCurve, msm::VariableBaseMSM};
use ark_ff::{BigInteger256, PrimeField, Zero, One, FromBytes};
use ark_serialize::CanonicalSerialize;
use ark_std::ops::{Mul, MulAssign};
use grumpkin::{Fq, Fr, SWAffine, SWProjective};
use acvm::FieldElement;

mod interop_tests;

fn deserialise_fq(bytes: &[u8]) -> Option<Fq> {
    assert_eq!(bytes.len(), 32);

    let mut tmp = BigInteger256([0, 0, 0, 0]);

    tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
    tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
    tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
    tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

    Fq::from_repr(tmp)
}

fn deserialise_point(x_bytes: &[u8], y_bytes: &[u8]) -> Option<SWAffine> {
    let x = deserialise_fq(x_bytes)?;
    let y = deserialise_fq(y_bytes)?;
    let is_infinity = false; // none of the generators should be points at infinity
    Some(SWAffine::new(x, y, is_infinity))
}

fn naive_var_base_msm<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInt],
) -> G::Projective {
    let mut acc = G::Projective::zero();

    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        acc += &base.mul(*scalar);
    }
    acc
}

pub fn pedersen(values: &[Fr]) -> SWProjective {
    let values_repr: Vec<_> = values.into_iter().map(|val| val.into_repr()).collect();
    VariableBaseMSM::multi_scalar_mul(&generators(), &values_repr)
}

pub fn pedersen_naive(values: &[Fr]) -> SWProjective {
    let values_repr: Vec<_> = values.into_iter().map(|val| val.into_repr()).collect();
    naive_var_base_msm(&generators(), &values_repr)
}

pub fn fixed_base(input: &[u8]) -> (FieldElement, FieldElement) {
    let gen = SWAffine::prime_subgroup_generator();
    // let priv_key = Fr::read(input).unwrap(); this is broken
    let priv_key = deserialise_fq(input).unwrap();
    let k_fr = Fr::from(priv_key.into_repr());

    let pub_key = gen.mul(k_fr);
    let pub_key_affine = pub_key.into_affine();

    let x_hex_affine = aztec_fr_to_hex(pub_key_affine.x);
    let y_hex_affine = aztec_fr_to_hex(pub_key_affine.y);
    println!("pub_key affine x: {:?}", x_hex_affine);
    println!("pub_key affine y: {:?}", y_hex_affine);

    let noir_x = FieldElement::from_hex(&x_hex_affine).unwrap();
    let noir_y = FieldElement::from_hex(&y_hex_affine).unwrap();

    (noir_x, noir_y)
}

pub fn aztec_fr_to_hex(field: Fq) -> String {
    let mut bytes = Vec::new();

    field.serialize(&mut bytes).unwrap();
    bytes.reverse();

    hex::encode(bytes)
}

// TODO: make this a lazy static or check if we can make a from_hex const variant. The latter is harder
fn generators() -> [SWAffine; 128] {
    let mut gens = [SWAffine::default(); 128];
    for (index, [x_hex, y_hex]) in GENERATORS.into_iter().enumerate() {
        let x_bytes = hex::decode(x_hex).unwrap();
        let y_bytes = hex::decode(y_hex).unwrap();
        let point = deserialise_point(&x_bytes, &y_bytes).unwrap();
        gens[index] = point
    }

    gens
}

const GENERATORS: [[&str; 2]; 128] = [
    [
        "2619a3512420b4d3c72e43fdadff5f5a3ec1b0e7d75cd1482159a7e21f6c6d6a",
        "228b620062a4113580780b27bf4b5d54b057747b51eab3d635902ca775ad495b",
    ],
    [
        "108800e84e0f1dafb9fdf2e4b5b311fd59b8b08eaf899634c59cc985b490234b",
        "2d43ef68df82e0adf74fed92b1bc950670b9806afcfbcda08bb5baa6497bdf14",
    ],
    [
        "1f9d92dd9736dd58f5e36e29ba9f6be50e280e95b5024a01d4727206c595a0e3",
        "105d89383923e85a414837357881d920cd0790bb76ada3dd5c9285e0cfea396e",
    ],
    [
        "1ebe8c72c21b40cf102ce8a30ca716febb0503334aee2223b02fa49add4cb383",
        "2faafda7c9066279e11f28625945ce370743356f0325f64537f69c12e0c8bc42",
    ],
    [
        "15c090b15eb9672678774829a0732314e0f365236cfc1958ff320b44d6e9b3c0",
        "20db64cab0a3bb17e61b90686b8d2ad32a3e859e45c7458be8489cd5daa1a054",
    ],
    [
        "2732d1bd60aeb6648d280ec4ad7fa0b825f68963b2ac1d72cd5b58a65843f4c9",
        "0456a58576d979cec45075b094b05479f7a3f79be931e2a2e22e476cd652efe1",
    ],
    [
        "1233e0b70382623530e7cf2fea3b974bbd82f116f084e177dd7c86f996f312bf",
        "13319fe232dda8465231d26705a040b98b9a7d7ecaa663f39bad2737c76ba81e",
    ],
    [
        "00a3e6a1807a34ec7dac54b6d4eb3faa46b4d56666892dc3511f27fc9ef016d9",
        "199316709dd1858c735b18dbac94eaef90db388ec304895942fe73c6a155f578",
    ],
    [
        "1c18857d44b175631db9142939659bc42b3d74879abd41a39e864ef9ed4f4ce5",
        "0e84ffe04578845a4a219a8347e5f89306e8cf22487dbfabec7a0a93016be3df",
    ],
    [
        "04d23d0aab96201f8cc90c724deaaad9151632746884957c511fff0b56e5c2ba",
        "2c84d1300e571604fc41983885f57046dbf4ebc2b23d53e32c0ad521225a03f4",
    ],
    [
        "0fc8216d33719d34588d1b8bcb100478d0b3be580b0732e35b905cc696f60f8d",
        "2658dc066d013bae8063d4b7cd576ed2f25c2ec09da83148a1e4dac89dcaf011",
    ],
    [
        "190d439d97b0e151e7cdf87c227a41af59eb086ecca2046ffa26cb82e1e89e6d",
        "08cfc2c50ba022cb475217fc665e62e4b48e4e32715824ab55e2df65d3a30155",
    ],
    [
        "2689e9ab7e205a59edda3870664f6e4b55ba85cc2d201cf2af6f43047d319427",
        "15ce484eadacef3b7b85bed71091ef23c486eccd37fbc5fb61ec55568dc32801",
    ],
    [
        "2097b401f7119501f6e90e19588134264ce28325f5143dbbf4ece0f113beb3e0",
        "2d8dcec6eb395d93b63fab9f0cc5f6bb17960e0cba942b8b7620c5f26837c23f",
    ],
    [
        "1819bf407882ba66c7ec503183d7fec3a4804e840bd9e8ac58e7c33306ca9751",
        "178f863a560349341d74ded359e2bf2e406dcd418526f0d71d5c6f50018b74b6",
    ],
    [
        "02addde3c40a26053a7802aeab119da5cca90a82938df2970d8c915657353e8c",
        "21ac9a7d63e0784a750cd3096399e06d1081c57d731e59dc965e6e25e4b67aeb",
    ],
    [
        "1db25b242d06175742e65b5921a41c4c9fe5be1c28e77d0b0724f0f1ee596ddf",
        "2986bc0c8095e9354281e8b5017c86a4fc51d77a6e89147fb4097588a3ad389e",
    ],
    [
        "178237b3716315a1d3a94a741415487fdbd084b23fe4a7f01ba32273d7928289",
        "0a8f499f175462b77bddd4c0bb9e19931c957844531e5b83167077a70c4360b9",
    ],
    [
        "2358634e71c2578a45898151d7af926af903ac7b2b397d43933a1bf95813a2d5",
        "198d4a4e69bb68f9410fd13f15bcd63cb0d6237cb549bb1f16ea9be1aa10425f",
    ],
    [
        "23f702447f5b99ea2d67cb68f3392ea02da355bcea57c32289e382b527329384",
        "0f86ffadb3a64a6f3d34c8c43250d0c744fec0d97435c80f4649ff0743853869",
    ],
    [
        "1f2566264d234c406561c1fbcd72643dcf58776e2de9a2b1cf4d3e69b1e98035",
        "08e2034f8bfa456738f609a44ec6e20dac8321ebee0915d2417d01576c35b996",
    ],
    [
        "19ac6556ad0e016c1cb011f9258a0fc39e897b91514bb5a26eb77c2ea3e8ed3d",
        "12e713b3a8386b57510dca04161233605eed140aee88c5ac55b904d96e5158da",
    ],
    [
        "26ea9d3a9e7c7bd58cca96bede246b31ab7b4c989ff71604ad3b65d2f41fc96d",
        "00d85866f8f475ea28ae5ddb03dcc5b3b55cfbc769ee46d2c6288cd1d64472cd",
    ],
    [
        "205004579563892458ddf0cf1371bf11e7287395f61cfbca30c8a8f2c0bbb2d9",
        "061047fa06992711b6b2db7cf1bb00d8257ff2d45ee5b285d21b4f24d703a392",
    ],
    [
        "1d50808bbd6ef9035ac1314645a94fe3e8b84e5dbd26ceae20283d6b2da547d0",
        "1224fa81c5edff0484da51e4ea673fd0364d3882e1305cd6176d9ac95be4f139",
    ],
    [
        "2984d37444840fdd9cc461abe0aff9702c5c4adeb4f42ad79f691bb1852dfc70",
        "202fab19a1003ae2e95005424fa0db14292a1f0bf126e57e07e1439250646b2a",
    ],
    [
        "2e6e5670a6cf0b54602a919cf8b2c3be29c4faef7750ce01bc19fab070ece09d",
        "0a0c9feaf433dfb08c1098801744001a645426203d8e3f14e019f922b6e06792",
    ],
    [
        "0e3481d1dfceadd3a770a232f1b788fdc2d3fd66fbd370c8b2e979741e246dac",
        "0eeaa1391c276c58abca7c725e6cd6be4fd68c18c342ed1ae1f438fcd62cee11",
    ],
    [
        "0a8cd72a4b5924a8403b9174fd759979b5ed03bdab6330ba8d8418cef43d9448",
        "1a3d60dd0ea3adb8924e28717f71a548cf8e18cbc1d9bfab13409021ef3094fa",
    ],
    [
        "16315088de3ae9083670af9fceff57a6fdd7e4533fca8b9fe262a3f930d0971c",
        "2b125773286bad5645946d55a6a7cf2d455e92c0f3f97226eab3fc8ea427e671",
    ],
    [
        "1d42b8e28ece2ff8cec9d6cbbe6f41d0ed8b3af205a69b3536e2c7997b912c23",
        "0c0f5365381038ae2fd5170a51895c3eb73c3193f256fed90ad6d3ab877a1775",
    ],
    [
        "06609c1ebc79b330293994fd59b873b73ea03804b84a707c51149fd83b18ae01",
        "2830123c690587d45ec3663a26fd03b08053ec99e61da09b7090f653d806abfb",
    ],
    [
        "253f80d135673238f42ed4264716dc0e13bacb6fdecd82f8ed2441a1c210d0e4",
        "2f74344cbb3b94b5a51ba915634d9c5c61fc7e5c51cbfcdd6ce1e41334117eb3",
    ],
    [
        "1048171b98e1ea87d969d2576cc3e76d33a87458dfd73819ff908bdce9e44992",
        "0359910fc217dc7a8752364f4332900adf97f5f3cd867c2a82ba78198e884a41",
    ],
    [
        "147f9366f9eeeb6c3f4a8dac0b3f839efba6389fa9e7c66b489ebc119e41386e",
        "1ad2ca85f75ee07820c6148a8ba928feb5bd09ac06728befd8e731d1943a114f",
    ],
    [
        "19b3f24cc6a325c016701b63608d22aa1ef6209e1bb8a157a75692147a7a304c",
        "15e28568518fd514c331e501196c1db650d9e983ad6171b0319eb48594d8ed04",
    ],
    [
        "0ff9cdf29824b431678d174139490b24cd4d22730937018fe876e6bbb4a5a654",
        "29d61d9f9b59115074ea0ec5ca9a083252786dc6ebe3348349aa9c421d6ecccd",
    ],
    [
        "20e85b5df653c7081a5be25851d56c6a1aaef6886a8fa02add2bef47c57fe316",
        "18a19a2a89634eec05046cc1cc2313c399bacec729092833db330432b0925f30",
    ],
    [
        "0dae6aa34f7e3a524aafc43179a12573f6935e9efbaa0c6ba956ee659731e36e",
        "28b539f24de56ce17c661cb88f10f420e32357636a072f0b753019ffa21560aa",
    ],
    [
        "22265f1f3c0ce1983c46bc2ff07de0ab43140d1ece286f923a5fac8b4e72e14a",
        "03a8bd7d9375d6dfbe5893c5054649aa421470f15bbb29404924341ed6f7044f",
    ],
    [
        "251a1b5138f9ca679e44ceec2355a905ddab20f847037160a87f00e592eb020b",
        "2cdaf6170ef983afa83cf769bc4f2baf75a5c14ceed352a081fec9348133025f",
    ],
    [
        "1bb839541a3bd5533c16d0897fd66b41362c725b451a52a7d9fd5b3cb1309488",
        "0f5326ff6d6b8c10dcccd603ce96d7020ea65b2d7c80e1dea485d67aa4ed2c83",
    ],
    [
        "05384acacc0ac61f3886c9e592a55c7322a6ba6300f49f404f54adf060ee30c3",
        "117cbe7925cc3e25c65fd5bb84a7efa8f27b49098bf963eff78e0439fa9aea78",
    ],
    [
        "13b501b41ff6af059fbe3a0103942b5c795725927e5bb4fb454472417be7c6e2",
        "17f8531d085f12e9fe65879464661b04ac282827bf048794bb8815d5beaa55b5",
    ],
    [
        "19e7d114b04268efc90cde71998c1a1357e7a21521f8cfd7a31b04f3f43c46c3",
        "277744fd9505018d1352f7bac7962f9f22fb447a09b5a29b6bbfe0be267d5729",
    ],
    [
        "0bf9e7fd52a73feb43bafd3fb3e6c9ac75c0e4c4c41a15a8c85e0a480393376c",
        "15927b4d0544a2d78c2d6da74ec685b18e8dcc2504a255ba1971ffa50c050895",
    ],
    [
        "03b9ff3e3388c31d8f80199326af1ba99312e0380c4b273075c1c4c511de5608",
        "106bf84da09a8e8af1779f382e517138902c81190c4008fc3aad83fbd41623e6",
    ],
    [
        "19fdce15d949df33d53e961e7118b54412eed5369afa6ab22bb93013671632e4",
        "17a74d6fe1a94801cc20edc8b18e01b426103dd28d2024ad53979596736bc2e1",
    ],
    [
        "230c231278ea6900b6da3b260fdae7dda256cf2260228dae2e8a8d18f7507b8b",
        "2156203327c9e0b30d51b8ffdc76436358ecc01d85198049a494b1466babcd93",
    ],
    [
        "2bb86e93753f947290d3820d8753a4fdc13c6cb069c9e748cc23d703a3ea22f9",
        "1e10f047a553c8af06f894078682830a4635a3bd448f7b76529c33fa12a2ad34",
    ],
    [
        "15eaf2b377c645abafbebf65836b96335cf9878fa82585e3377aa000be2ec3cc",
        "287fd820865173e6705607658cb06db50c9c9b1cda2534ed71ca071f52171875",
    ],
    [
        "21b5e5f6edb06c0f9a1c7d767f83d31c1ebdfe155adee7e268654f6b6abe14dc",
        "1d4dc155479491a83db619b2e50109e36b65ea22df4df944f4b4e3d9349f97c6",
    ],
    [
        "117bcfd9f9b462f2e62eefc284ea7a6e5073f37a05f7c187a6687918ab298d66",
        "0f690b9723c0afe2ca9ba318b8a09ca501fcd085bb364e1cbf8193beeff0868a",
    ],
    [
        "2c4634b20b1bf3c1958c45561cdf66b4878c643b84b08e760ece75a82e69c473",
        "18020c6bbd6cf54d3d60d3621b5cccda7a50e5a870ff73e05a37059e9fa6898a",
    ],
    [
        "0bec3393f79e2366846f7efc6d86440efbd39e216029a171e4148e2e74ef3321",
        "2fe41f2efc47c20b7caa2fa8d875d18520e28a0118134a9c9b24b04f54be5948",
    ],
    [
        "176eabb2a266beead9b7f75de534d8fabe3c42d9b020e23803479e62424e93bc",
        "13bd2aa39ed971ba1245ec6eac16693962f56583e8a487b2ac65cd6007bf0aa9",
    ],
    [
        "1db6cefc2c6da6cba7989be95f96b2f947fc39a880f490707957eec153cbb3f9",
        "0c5d120a7ca4f6fe7bad10f589e39fc4d14ebca2a232cb592257d26d46c1ced3",
    ],
    [
        "0419409da10ef2feb0a219a0fbf4ae681458168a9f89937c0f6e8a5f2769cfcc",
        "27a752caa0a978fb135a9d5325449a5c55bf1b181c01bf2da2fa3ee1dd9eb145",
    ],
    [
        "07ffe556e670f566c21346667d7a4eb490fa328fab076562592342151d6ae669",
        "2e797a091b6cb46d7fe41946cf150f1769411807fc9ca4d7de386a47626a43d4",
    ],
    [
        "2034e035836d95130aaa2099bf8c5c9f4385086143f463e6b6bd5ca8b581650e",
        "208fffb629c29426fda360d68e021516874955963ca99a9121dbc307d045dacb",
    ],
    [
        "1c88bbeaf3306b9aecaee0a2945f5cfe838dfb0080223c43e652a0ea9235cd2f",
        "213a8c0cc22266aa28703c89f2a1e5e2a8cae37f46b4ad7b42a04fc00634ab70",
    ],
    [
        "1eeeb5556894a3e32306c8f26fbb245a7adf1b165f073d0a757a1d433743e263",
        "18c175ccaa7c3f876109a56969218efe1331455d136d75d05b1b74a71de0d7ad",
    ],
    [
        "1cd51cc93fb89025b740aab2357ff0dd335a17684f02fdf81bbbff3dc96d802d",
        "212a89ab216d553489b3c98e390e787b9718b25c5b970f5d5c0518a9e91f5955",
    ],
    [
        "24f09eb76cacad2f4aa9ed63e9ff04373dcca31f6bb84bff0267fd87e23837de",
        "20394e9696e5f076ab96e4fe89e5ad8581f463f0edfe2831a2cff86675777a80",
    ],
    [
        "10bda3b0491357210389098e8c9eda8d25505503d67f25180d8384edea7369fe",
        "1899d82ad9a621292ebaa7fd8e44ac4393e9d471c6086a91f7037be34de128f1",
    ],
    [
        "06e113a36114791b5178836fa4f05026b66bd78cce0d39253ebdce421852d711",
        "2515636561fc6f981a5c77f0c29c2589b12362e592a9071b80c34328e7f3a6e1",
    ],
    [
        "10b9b76219871b16c6e6e009fa69ff639b0922a096e7a1ae90a9072f0c8c6bfc",
        "1cdc230e942092a21e78a16909afe1492825d11a70a5219ef5572ff57ce95598",
    ],
    [
        "0497cefd265c21f4c06c36aefb7995714b266d23cb5cf61b0ca1ca7480c1b073",
        "29682964f6a0caca5f0dad484a88540f1f22870584799c1376a11813f8b5c43f",
    ],
    [
        "0e56cc22ac46fd1793cd2269cce75e3140125a75489594682988ba6f6c641863",
        "07cd8865d313e2189e4dd93d3246285566b91ca19836f68bb2933c17cf042264",
    ],
    [
        "2cbc20239c7d7b873377fcff6730b6b2123f38ad0772787fd3847075418e420c",
        "0d2013b461b6ef74575a526411b405a2e60fd9fff5aafbd7d73b42034b034c24",
    ],
    [
        "031de5e14c1dcef48e09151c339fe083f1600147017deb1794346cff5213aac5",
        "2de8722869939a38b83eaf360cf7fad58c08ed9f6588ecad08edad1ff639dda7",
    ],
    [
        "073244f2e50fdaadaf2965bc400a2bfe1c23606203f3c80fc2d8421f06794fef",
        "16dd17ea336ff255127bcd12919fc894f90696862788bdbd868f5cd0c20a7224",
    ],
    [
        "1c12e280b5c7d10db097faae4380a23834d6af481cfd255d2b32dc210e828337",
        "2722575f1bfb6458614c9c3dbdc276f295cba33ea94357d3b24fc5ca1bdf713a",
    ],
    [
        "0c815311c0506e249a47cf843bb5594cc51499a44b0ced56436f34fdba4dd4f3",
        "2ff8e750426c12420a6b773377701f13848c07ae6b4631134b0ca470442c75d6",
    ],
    [
        "209e4c74f7d97bbd939ec0126cbe37eba521bd8c6355fa9806b98ec847462d5d",
        "0ab3a4ca17faa047193ffd7f3aa97ba8d2afd899cde55b60f4e5a88f33a369e1",
    ],
    [
        "0217b384348e0c142ed9fbc8dadb4f6708907c6e781826e430995cc7b9d52c2a",
        "25c587e5021573077bdcd582ce92d9da7be55a6568e6521a9e2080d7104a703f",
    ],
    [
        "093887050a9edc6cc81f4a7166fce046715a667b3987225d177ad3a64150fc0b",
        "29d521ac30f0925e8a5d8437668ffea21527f8e31367dbcce1462c7592c3d25e",
    ],
    [
        "00eb93c9dfa8ed6d6b64d79908694b97e7b20fbd48148e9a1227647f8da57ce9",
        "302262cb7f6230894a066294f5817c0efc162fcde54e147e4af13910c91cde20",
    ],
    [
        "2b994d1d1ea996a1cade15572493ef1b61b4b7ea1f7bf942f195d28dea4f3157",
        "04f0096ef024db90691f17afb78687f1451c6889ef938e837ba382f37f474d7c",
    ],
    [
        "27ca6053b6abc9dec3d87d9b08605ed6b76f2a3806a9332b4e341c1bb84395df",
        "1e5a285d29e59fc8b850a1af3b1096e59c076773f28ac57b559969490dc85c9b",
    ],
    [
        "13ecbccd3a9e45130bc2c12c30e1c30095451387bf4e482b234f853ecd8fa248",
        "21c093c56d3529b04228d11b0ed3d71c9b3bb1d79503e7ae6b9c041fbbe00476",
    ],
    [
        "297e2e76eeb690b37fa6ba7eea485475d7440238218990a0e7750bad4a27a2ed",
        "17890ad86cb0bdfb3f7ac6621eb8fa92c9646bbfd86e14e03e48b32084eaeaf4",
    ],
    [
        "120c3a7c88441e3f7c3b5da0ec7defca1974b121196032b5c840b95438360789",
        "076c304a786d4eb24564bac846ccdc52d105807111c9c240045e6871227ae74a",
    ],
    [
        "12f2baaf5dbf5f4db1eaa5bcfdef11d3d9ee79e1ce16838d1746b26f221c85c7",
        "30547bc8df39b04602d282fe36bed4ea3a643f7a3a46ad64b5069a22ecdf92ba",
    ],
    [
        "2166f74e80db5144a073ef661a599195fc1b3c5477cc9ca8980bfa7fc6f99e1b",
        "188433ff838525f7c4bb9a491d731f6ba7f13e8d8b0efe41a143bc68a4db6e05",
    ],
    [
        "11455986b01033fbd7d07dbff1d77bb592990d9061500fbe4a2204fd4544db10",
        "0057ea60ba0b65ab38a36f02849875c634a505ae0ba4f164c100f625056416ad",
    ],
    [
        "3050dd86e93f5d03957e7fe8cc8a21fd559208148c0510fe0747e5c0bf7fde95",
        "0029397335de0ebb8fe7795805ee1ebd3ba7e1c6cd1b95e6c9a3a66dfb1bf0fc",
    ],
    [
        "16cd25b48026f5e62fee9807daf2002bd0495ab4a0885112cfbda7733d1c1c46",
        "10a21828fe5bab915e90f2394c54fe072eb2918c487d4a59c423c1c976369244",
    ],
    [
        "1857fefd6b2e126539156f1fb5cb0d815ab2da6ec1f995665918f366f8ef4cc9",
        "20dffba7d2c16e7f1f6086215695fc34bf295b824f8efa67febd55bcac7e3a56",
    ],
    [
        "130b16997ac11922c0d0bab29a9334af9111121b7d828447a7104671cf153ac1",
        "1371b365c4b72a3a5bfef7726b56eb7ac1c520c89b8288cc95ddf53ffd381c87",
    ],
    [
        "2e4a0e45c9abe40a17774437f8815fd4a29adcd699cba15d1aeae09265c9ffbb",
        "0fdde4f9aec239dd938449de809a5e4f3ac6705646126ef04d5cd29c8435ba5e",
    ],
    [
        "2b743b6c8b5a8cc905bc3237b3987ddbf1d73ef498fefefeaac126e71750772d",
        "298d0eabd471610b76741157a6daabad6bccfff34fa8cf06a1253d67ff366d71",
    ],
    [
        "219fa9511908b44385110a1e6eb60803553e9f70fb05229943d1594e3d95bcb3",
        "23e0b29d22607939e77b457887bdfa0a9ef4708ccdce88d7fa0f6aafafd4cd59",
    ],
    [
        "2dd37090fafe08ef854b221fa985321783daf4dcad0d8950c888eeeadffd6f6a",
        "08e85a7cb6d094ef6b096cc79e1ae6d3ad8fd64dc4e483925aec2feaed8005b3",
    ],
    [
        "0fbb9bc106702576771f4525a862d319fc50cc96b147e9f51471b92b472cfd7d",
        "1c352dd9949ad5d137b56384093102e5a0f172329b2d9eb5912dc26f71450bc4",
    ],
    [
        "0ba80e16ab8948dda79cec5537a8696e8087a2c33db595fff25f2e77488a26d6",
        "301509772e75e898dbb2eafd960c5ca86a72151c04780fea21f720670b6d720e",
    ],
    [
        "2f331f819d7abb0d8d6edec438b6c984fe315fd81160009c1c3b3c23d1d16e5a",
        "0402674b4f0b485a4bd570e349431ff0c0f2528f84fc0b9cbad83ed94bf0ab2d",
    ],
    [
        "0a933d14ad86ffee76aa3e6ac29aa8c30c69758dec8fbc69454aef5b1a6ed883",
        "0c35d236c7d26cefc6322f3aed9669518560049da5ac7787828cb2df7c7a1e23",
    ],
    [
        "2bac0d4cb85e47bf9a725f0712095a76228afca77a7b05b77b4e993d1591dbcf",
        "210934489b8d29a5e29ff9766513a6d7e0e3e7bf64f027e5c08753f665d735ae",
    ],
    [
        "00f7c23e38349e3c72b5fa93294eb323f4b0341e446e65bca5f2be488fc9ca21",
        "2ce23c0153f4c2e860a28195fbf52b55a0d6a690f461a410dd63ac29c695c9a9",
    ],
    [
        "167fe456fc44495e286bd9cd9662835eed243d0bf0f0143eb8d3148f9c2e367f",
        "2a2129047dd154f73249628f48e57f256c3297c8694da60f49375b084fbf2b71",
    ],
    [
        "073a688cf494339d765d870775a1c20f6f6dd54abc28573ab6e146acb3963455",
        "09514347ab1079868b536debde416e98d036234e11f73554cb1ce36127c53729",
    ],
    [
        "2ecf2da5f4630e6e6d4847005f96f57701a6e038af7e75ca623e3b77079b4396",
        "1368849569c0cb677bddb78a354bcd0ee9f9bc89e0c79532284666260315d992",
    ],
    [
        "227c864f03ed67d27bd23a8bc0ed6d1459855d5621e20c9869ec69ed20b3092f",
        "12c588991d0e9838eaf3dee6145a7d261a4a1fabda459ede0a079888a2188c81",
    ],
    [
        "001942f4ab143b7143b20e460bb3f7b17531b9d1abed4032a52785f1ab2c8ed1",
        "013b3d5bcf81d4767a22de8c7afc8ffa897cb8f6cf9284062e7224f1f57acef9",
    ],
    [
        "03088872461c444ac75c33c24fdd067911ee1ed84f38b63bed8a4975e3c19af9",
        "29d22629404c4ef33a0bf398ff529fed818e027328b7b8e0b280e3eedd3f7652",
    ],
    [
        "2d99e8f41c8de36fd990b5511fea190768082c3577fad9dc12c494241a77d1e0",
        "2a08f185e4e41f1c4c2a14511d31a46423a03e0606f84b61acf5acb3b4267259",
    ],
    [
        "00eac0fe3717664dc8f22dbb3904ce2db51dd322e94ad64121a569cad1902b5a",
        "16b7089428f3b19bf91e961ab95215454a981f6b72530e961388f3b45df313ac",
    ],
    [
        "1dd22f97ba43e6133bc59d5fcf096105bdb552e2ad3e08ac6172fc37138764fe",
        "25f6dd6e36394c3c910bae8de822e66924c910fc88cfabf2dfe340c6a13d2de9",
    ],
    [
        "10185a5393bed5101577c48303c4b5f5d035ffdd48f7732470f4996d9ebac863",
        "1489409efd1a47a2a50a34bfcbe0e038332982a7bf0b2266dac9938f3a8c4986",
    ],
    [
        "1a6633405ade921a58eef888caabb0b96e97402d43f877b2564f3162d982c7c2",
        "2b88335e93ff3f9b1f5be4dc12218d5dd3e02d40f9abb3b487e53cc829c3dc6f",
    ],
    [
        "29749a7de6a504a6b9fbc8a67756469773a3bf72f4878e1ed807f226ac3a9ae0",
        "1cf454d2659a4f2d63b916555134ec5e2841d2975e39c4ace37e0843d046b06b",
    ],
    [
        "08fcb9f741f605e09d389f1bea8e1d4911bbebc0569d75f4d1856da200d4e5db",
        "0adc4f074d819ab6d14f7f6afca41d4d0f05e8230ab1daffb9ec89b1c60cd9e9",
    ],
    [
        "0a1966fbad0c3e5952addf628e58515f12c86f67cbf1e17368477320eabc007d",
        "0e3ca74a46331feae6dfeb8f57185cadcc236c3aa957492287ec18691fac6e9c",
    ],
    [
        "0830dbaaed5b479a1300eeda0675905d5bd51135bf16a78c216663445ff4a605",
        "1eb4048b71b27adfd9ffd3a838d58a855bd9137742447e8785251ff73019404e",
    ],
    [
        "1ce41a36b20bf3b7ab833f718fb1241428396770a63c7d61b184e6c97d8d9e81",
        "066dc9b6670aba79b37be82920b7eca5e972bfc563991420f2c4d82c2da9f658",
    ],
    [
        "009ee74ab22e570c1468ae0d726d98daca91d1ea56cf9932db4dbe54d99c564b",
        "1ebde7a3739fa9b0df1f00d2e482b26725a9934b6ec6735b3038ce3682a0aea3",
    ],
    [
        "0ffd3d4ed4aca700e05291cd5a60203a35c794516e221bc7a111cc702d966301",
        "11ec732e483bc28e12d8adb1a2ee0f61dc40b92038ed1bdc00a87621ace7b13b",
    ],
    [
        "0097703c944c57e1d869200c1f7f81286dae25067e269cee6ac2a630f1fc5a75",
        "29e19c5306babb6e9d7b8adebbb3f8dc617d672dd042fd5139f67ff633deb2fa",
    ],
    [
        "1c03a09c2d8150ce23db4163bee3e8003d68a0c433f624b7e03eeb154b1479ef",
        "09c996a513f15d77dbbcb7e4f44f0c06c4a5a5bb171022449be04d6d1b49f3cf",
    ],
    [
        "27517042ac687575bd4d2d056fbeddf018a62ce0fbe5d3c5d01abcf374397002",
        "024dfb234e21e6dbe09b6dbdc6bffadb30ce7501fc4361a564cf2b6aa119e4c3",
    ],
    [
        "27fa4e06cd3cd416aabd47beb7f917a18046256716d0a8f541598463397dcb27",
        "1a6e2312bd0e889bc0c805b0f287d8c815ba25c6823580bbba49deb3064c7fad",
    ],
    [
        "28ae02c10a1ae47ea75191197f205d9e08b11fe50c1d96da72334f81e95dd7b0",
        "138e9784a38a47da7895eb8d306bccbff05db45acfa9613f6f43a67b4ea0510c",
    ],
    [
        "23aa404b0e3406e1224d662acbc1eb0afbd27fabbd3d9f65e6a537ecd016b6d1",
        "156c6ce64bb6bd8278354309da5f0643390cdc315f3bb91d037bf463a0827c79",
    ],
    [
        "280c9bdd15612bc10972ee701d2fc147626ff1ea1c3010032a495122228f6099",
        "0441492730e13d3919a0343bc985053c1d0dd2e75f190b0dae3f6ebbc5143f66",
    ],
    [
        "0f7e23182e1f928de9faab7ef881b613e719aadc54dd3e3d7ee31ef2c0c1f963",
        "00129031b79bd4ff5d24c490a885c9df6265fd8c53519f9cfd5760556f934636",
    ],
    [
        "031f1031951b605c78f2eff2ad4652a8f8fa4f5230821bbbcf3fab680d5ae76f",
        "0461f40460e9ca28b614d74bc38b77f033e8d3f91edf5261b67e5e2aba374faa",
    ],
    [
        "1668dc28c08e41ccb0367f9dfe605805311a1cd87fe1bc891d4c138666832e35",
        "0cd9e23f92d0145f605762ed3d915fd4e8a8883de8d97b2e23d513aaa24d5164",
    ],
];
