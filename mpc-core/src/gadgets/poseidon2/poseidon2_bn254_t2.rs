/// Parameters are compatible with the original Poseidon2 parameter generation script found at:
/// [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
use super::Poseidon2Params;
use std::sync::LazyLock;

type Scalar = ark_bn254::Fr;

const T: usize = 2;
const D: u64 = 5;
const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 56;

// lazy_static! {
pub(crate) static MAT_DIAG_M_1: LazyLock<[Scalar; T]> = LazyLock::new(|| {
    [
        crate::gadgets::field_from_hex_string("1").unwrap(),
        crate::gadgets::field_from_hex_string("2").unwrap(),
    ]
});

pub(crate) static EXTERNAL_RC: LazyLock<Vec<[Scalar; T]>> = LazyLock::new(|| {
    vec![
        // First external
        [
            crate::gadgets::field_from_hex_string(
                "0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x0c0356530896eec42a97ed937f3135cfc5142b3ae405b8343c1d83ffa604cb81",
            )
            .unwrap(),
        ],
        [
            crate::gadgets::field_from_hex_string(
                "0x1e28a1d935698ad1142e51182bb54cf4a00ea5aabd6268bd317ea977cc154a30",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x27af2d831a9d2748080965db30e298e40e5757c3e008db964cf9e2b12b91251f",
            )
            .unwrap(),
        ],
        [
            crate::gadgets::field_from_hex_string(
                "0x1e6f11ce60fc8f513a6a3cfe16ae175a41291462f214cd0879aaf43545b74e03",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x2a67384d3bbd5e438541819cb681f0be04462ed14c3613d8f719206268d142d3",
            )
            .unwrap(),
        ],
        [
            crate::gadgets::field_from_hex_string(
                "0x0b66fdf356093a611609f8e12fbfecf0b985e381f025188936408f5d5c9f45d0",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x012ee3ec1e78d470830c61093c2ade370b26c83cc5cebeeddaa6852dbdb09e21",
            )
            .unwrap(),
        ],
        // Second external
        [
            crate::gadgets::field_from_hex_string(
                "0x19b9b63d2f108e17e63817863a8f6c288d7ad29916d98cb1072e4e7b7d52b376",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x015bee1357e3c015b5bda237668522f613d1c88726b5ec4224a20128481b4f7f",
            )
            .unwrap(),
        ],
        [
            crate::gadgets::field_from_hex_string(
                "0x2953736e94bb6b9f1b9707a4f1615e4efe1e1ce4bab218cbea92c785b128ffd1",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x0b069353ba091618862f806180c0385f851b98d372b45f544ce7266ed6608dfc",
            )
            .unwrap(),
        ],
        [
            crate::gadgets::field_from_hex_string(
                "0x304f74d461ccc13115e4e0bcfb93817e55aeb7eb9306b64e4f588ac97d81f429",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x15bbf146ce9bca09e8a33f5e77dfe4f5aad2a164a4617a4cb8ee5415cde913fc",
            )
            .unwrap(),
        ],
        [
            crate::gadgets::field_from_hex_string(
                "0x0ab4dfe0c2742cde44901031487964ed9b8f4b850405c10ca9ff23859572c8c6",
            )
            .unwrap(),
            crate::gadgets::field_from_hex_string(
                "0x0e32db320a044e3197f45f7649a19675ef5eedfea546dea9251de39f9639779a",
            )
            .unwrap(),
        ],
    ]
});
pub(crate) static INTERNAL_RC: LazyLock<Vec<Scalar>> = LazyLock::new(|| {
    vec![
        crate::gadgets::field_from_hex_string(
            "0x0252ba5f6760bfbdfd88f67f8175e3fd6cd1c431b099b6bb2d108e7b445bb1b9",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x179474cceca5ff676c6bec3cef54296354391a8935ff71d6ef5aeaad7ca932f1",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2c24261379a51bfa9228ff4a503fd4ed9c1f974a264969b37e1a2589bbed2b91",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1cc1d7b62692e63eac2f288bd0695b43c2f63f5001fc0fc553e66c0551801b05",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x255059301aada98bb2ed55f852979e9600784dbf17fbacd05d9eff5fd9c91b56",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x28437be3ac1cb2e479e1f5c0eccd32b3aea24234970a8193b11c29ce7e59efd9",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x28216a442f2e1f711ca4fa6b53766eb118548da8fb4f78d4338762c37f5f2043",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2c1f47cd17fa5adf1f39f4e7056dd03feee1efce03094581131f2377323482c9",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x07abad02b7a5ebc48632bcc9356ceb7dd9dafca276638a63646b8566a621afc9",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0230264601ffdf29275b33ffaab51dfe9429f90880a69cd137da0c4d15f96c3c",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1bc973054e51d905a0f168656497ca40a864414557ee289e717e5d66899aa0a9",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2e1c22f964435008206c3157e86341edd249aff5c2d8421f2a6b22288f0a67fc",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1224f38df67c5378121c1d5f461bbc509e8ea1598e46c9f7a70452bc2bba86b8",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x02e4e69d8ba59e519280b4bd9ed0068fd7bfe8cd9dfeda1969d2989186cde20e",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1f1eccc34aaba0137f5df81fc04ff3ee4f19ee364e653f076d47e9735d98018e",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1672ad3d709a353974266c3039a9a7311424448032cd1819eacb8a4d4284f582",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x283e3fdc2c6e420c56f44af5192b4ae9cda6961f284d24991d2ed602df8c8fc7",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1c2a3d120c550ecfd0db0957170fa013683751f8fdff59d6614fbd69ff394bcc",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x216f84877aac6172f7897a7323456efe143a9a43773ea6f296cb6b8177653fbd",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2c0d272becf2a75764ba7e8e3e28d12bceaa47ea61ca59a411a1f51552f94788",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x16e34299865c0e28484ee7a74c454e9f170a5480abe0508fcb4a6c3d89546f43",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x175ceba599e96f5b375a232a6fb9cc71772047765802290f48cd939755488fc5",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0c7594440dc48c16fead9e1758b028066aa410bfbc354f54d8c5ffbb44a1ee32",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1a3c29bc39f21bb5c466db7d7eb6fd8f760e20013ccf912c92479882d919fd8d",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0ccfdd906f3426e5c0986ea049b253400855d349074f5a6695c8eeabcd22e68f",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x14f6bc81d9f186f62bdb475ce6c9411866a7a8a3fd065b3ce0e699b67dd9e796",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0962b82789fb3d129702ca70b2f6c5aacc099810c9c495c888edeb7386b97052",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1a880af7074d18b3bf20c79de25127bc13284ab01ef02575afef0c8f6a31a86d",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x10cba18419a6a332cd5e77f0211c154b20af2924fc20ff3f4c3012bb7ae9311b",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x057e62a9a8f89b3ebdc76ba63a9eaca8fa27b7319cae3406756a2849f302f10d",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x287c971de91dc0abd44adf5384b4988cb961303bbf65cff5afa0413b44280cee",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x21df3388af1687bbb3bca9da0cca908f1e562bc46d4aba4e6f7f7960e306891d",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1be5c887d25bce703e25cc974d0934cd789df8f70b498fd83eff8b560e1682b3",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x268da36f76e568fb68117175cea2cd0dd2cb5d42fda5acea48d59c2706a0d5c1",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0e17ab091f6eae50c609beaf5510ececc5d8bb74135ebd05bd06460cc26a5ed6",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x04d727e728ffa0a67aee535ab074a43091ef62d8cf83d270040f5caa1f62af40",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0ddbd7bf9c29341581b549762bc022ed33702ac10f1bfd862b15417d7e39ca6e",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2790eb3351621752768162e82989c6c234f5b0d1d3af9b588a29c49c8789654b",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1e457c601a63b73e4471950193d8a570395f3d9ab8b2fd0984b764206142f9e9",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x21ae64301dca9625638d6ab2bbe7135ffa90ecd0c43ff91fc4c686fc46e091b0",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0379f63c8ce3468d4da293166f494928854be9e3432e09555858534eed8d350b",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x002d56420359d0266a744a080809e054ca0e4921a46686ac8c9f58a324c35049",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x123158e5965b5d9b1d68b3cd32e10bbeda8d62459e21f4090fc2c5af963515a6",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0be29fc40847a941661d14bbf6cbe0420fbb2b6f52836d4e60c80eb49cad9ec1",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1ac96991dec2bb0557716142015a453c36db9d859cad5f9a233802f24fdf4c1a",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1596443f763dbcc25f4964fc61d23b3e5e12c9fa97f18a9251ca3355bcb0627e",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x12e0bcd3654bdfa76b2861d4ec3aeae0f1857d9f17e715aed6d049eae3ba3212",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0fc92b4f1bbea82b9ea73d4af9af2a50ceabac7f37154b1904e6c76c7cf964ba",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1f9c0b1610446442d6f2e592a8013f40b14f7c7722236f4f9c7e965233872762",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x0ebd74244ae72675f8cde06157a782f4050d914da38b4c058d159f643dbbf4d3",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2cb7f0ed39e16e9f69a9fafd4ab951c03b0671e97346ee397a839839dccfc6d1",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1a9d6e2ecff022cc5605443ee41bab20ce761d0514ce526690c72bca7352d9bf",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x2a115439607f335a5ea83c3bc44a9331d0c13326a9a7ba3087da182d648ec72f",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x23f9b6529b5d040d15b8fa7aee3e3410e738b56305cd44f29535c115c5a4c060",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x05872c16db0f72a2249ac6ba484bb9c3a3ce97c16d58b68b260eb939f0e6e8a7",
        )
        .unwrap(),
        crate::gadgets::field_from_hex_string(
            "0x1300bdee08bb7824ca20fb80118075f40219b6151d55b5c52b624a7cdeddf6a7",
        )
        .unwrap(),
    ]
});

/// The Poseidon2 parameters for the BN254 curve with a internal state of size t=2.
pub static POSEIDON2_BN254_T2_PARAMS: LazyLock<Poseidon2Params<Scalar, T, D>> =
    LazyLock::new(|| {
        Poseidon2Params::new(
            ROUNDS_F,
            ROUNDS_P,
            &MAT_DIAG_M_1,
            &EXTERNAL_RC,
            &INTERNAL_RC,
        )
    });

pub(crate) const WITNESS_INDICES_T2: &[u16] = &[
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44,
    46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92,
    94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 123, 124, 125, 126,
    127, 164, 165, 168, 169, 195, 196, 199, 200, 226, 227, 230, 231, 257, 258, 261, 262, 288, 289,
    292, 293, 319, 320, 323, 324, 350, 351, 354, 355, 381, 382, 385, 386, 396, 397, 416, 417, 436,
    437, 456, 457, 476, 477, 496, 497, 516, 517, 536, 537, 556, 557, 576, 577, 596, 597, 616, 617,
    636, 637, 656, 657, 676, 677, 696, 697, 716, 717, 736, 737, 756, 757, 776, 777, 796, 797, 816,
    817, 836, 837, 856, 857, 876, 877, 896, 897, 916, 917, 936, 937, 956, 957, 976, 977, 996, 997,
    1016, 1017, 1036, 1037, 1056, 1057, 1076, 1077, 1096, 1097, 1116, 1117, 1136, 1137, 1156, 1157,
    1176, 1177, 1196, 1197, 1216, 1217, 1236, 1237, 1256, 1257, 1276, 1277, 1296, 1297, 1316, 1317,
    1336, 1337, 1356, 1357, 1376, 1377, 1396, 1397, 1416, 1417, 1436, 1437, 1456, 1457, 1476, 1477,
    1496, 1497,
];

pub(crate) const WITNESS_INDICES_SIZE_T2: usize = 1498;
