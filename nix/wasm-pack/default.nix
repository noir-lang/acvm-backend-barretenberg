{ lib, stdenv
, fetchFromGitHub
, rustPlatform
, pkg-config
, libressl
, curl
, Security ? false
}:

rustPlatform.buildRustPackage rec {
  pname = "wasm-pack";
  version = "0.11.0+bin-fix";

  src = fetchFromGitHub {
    owner = "kobyhallx";
    repo = "wasm-pack";
    rev = "e3d52c8f9ecb2e5f58d0a90e68b5b0ee812a2dfa";
    sha256 = "sha256-8L3S8R+XxnLstg7vpRLT2UaQsAo6XKSu1a5B33+iIUk="; 
  };

  cargoHash = "sha256-VKf21tk5BcfSUYTETSO6Ckgd6Ne3LzeAb4gxpFaJpBU=";

  nativeBuildInputs = [ pkg-config ];

  buildInputs = [
    # LibreSSL works around segfault issues caused by OpenSSL being unable to
    # gracefully exit while doing work.
    # See: https://github.com/rustwasm/wasm-pack/issues/650
    libressl
  ] ++ lib.optionals stdenv.isDarwin [ curl Security ];

  # Needed to get openssl-sys to use pkg-config.
  OPENSSL_NO_VENDOR = 1;

  # Most tests rely on external resources and build artifacts.
  # Disabling check here to work with build sandboxing.
  doCheck = false;

  meta = with lib; {
    description = "A utility that builds rust-generated WebAssembly package";
    homepage = "https://github.com/rustwasm/wasm-pack";
    license = with licenses; [ asl20 /* or */ mit ];
    maintainers = [ maintainers.dhkl ];
  };
}
