{ pkgs, ... }:

{
  cachix.enable = false;

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_24;
    npm = {
      enable = true;
      install.enable = true;
    };
  };

  packages = with pkgs; [
    binaryen
    wasm-bindgen-cli
    wasm-pack
  ];

  scripts.build.exec = "npm run build";
  scripts.publish-dry-run.exec = "npm run publish:dry-run";

  enterShell = ''
    echo "blind-rsa-signatures-wasm dev shell"
    rustc --version
    wasm-pack --version
    node --version
  '';
}
