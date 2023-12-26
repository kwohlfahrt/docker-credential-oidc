{
  description = "Docker credential provider";

  inputs = {
    nixpkgs.url = "nixpkgs";
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
  };

  # adapted from https://hoverbear.org/blog/a-flake-for-your-crate/#flake-nix
  outputs = { self, nixpkgs, naersk } : let
    systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

    docker-credential-oidc = { naersk, lib, openssl, pkg-config, targetPlatform, darwin ? null }:
    let
      darwinPackages = with darwin.apple_sdk.frameworks; [ SystemConfiguration ];
    in naersk.lib."${targetPlatform.system}".buildPackage rec {
      pname = "docker-credential-oidc";
      root = ./.;
      buildInputs = [ openssl ] ++ (if (darwin != null) then darwinPackages else []);
      nativeBuildInputs = [ pkg-config ];

      meta = with lib; {
        platforms = platforms.all;
      };
    };
  in {
    defaultPackage = forAllSystems (system: (import nixpkgs { inherit system; overlays = [ self.overlay ]; }).docker-credential-oidc);
    overlay = self: super: {
      docker-credential-oidc = self.callPackage docker-credential-oidc { inherit naersk; };
    };
  };
}

