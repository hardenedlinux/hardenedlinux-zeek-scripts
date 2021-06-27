{ stdenv, zeek-release }:
stdenv.mkDerivation rec {
  src = ../scripts;
  name = "hardenedlinux-zeek-script";
  phases = [ "installPhase" ];
  buildInputs = [ zeek-release ];
  installPhase = ''
    runHook preInstall
    cp -r $src $out

    substituteInPlace $out/zeek-kafka.zeek \
    --replace "/usr/local/zeek/lib/zeek/plugins/" "${zeek-release}/lib/zeek/plugins/"

    ## top-1m fix
    substituteInPlace $out/protocols/dns/alexa/alexa_validation.zeek \
    --replace "top-1m.txt" "$out/protocols/dns/alexa/top-1m.txt"

    ## dynamic_dns fix
    substituteInPlace $out/protocols/dns/dyndns.zeek \
    --replace "dynamic_dns.txt" "$out/protocols/dns/dynamic_dns.txt"

    runHook preInstall
  '';
}
