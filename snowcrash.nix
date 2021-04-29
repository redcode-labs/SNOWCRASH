{ buildGoModule }:

buildGoModule rec {
  pname = "snowcrash";
  version = "0.0.1";

  src = builtins.filterSource (path: type: type != "directory" || baseNameOf path != ".git") ./.;

  vendorSha256 = "sha256:gKBOSs2BjqAniCLvsEE+sFESpHvbrOiHymriSrL0ovY="; 

  subPackages = [ "." ]; 

  runVend = true;

  buildInputs = [ ];
}


