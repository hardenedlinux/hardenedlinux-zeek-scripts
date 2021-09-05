{ stdenv, lib, zeek-release, hardenedlinux-zeek-scripts-sources }:
let
  loadScripts = lib.concatStringsSep "\n" (map (f: "@load ${hardenedlinux-zeek-scripts-sources.${f}.src}/scripts") scripts);
  scripts = [
    "ja3"
    "top-dns"
    "dns-tunnels"
    "dns-axfr"
  ];
in
stdenv.mkDerivation rec {
  src = ../scripts;
  name = "hardenedlinux-zeek-script";
  phases = [ "installPhase" ];
  buildInputs = [ zeek-release ];
  installPhase = ''
    runHook preInstall
    cp -r $src $out
    chmod +rw -R $out
    cat <<EOF > $out/__load__.zeek
    @load ./protocols
    ${loadScripts}
    EOF

    #################
    # Fixup Scripts #
    #################
    substituteInPlace $out/__load__.zeek \
    --replace "${hardenedlinux-zeek-scripts-sources.ja3.src}/scripts" "${hardenedlinux-zeek-scripts-sources.ja3.src}/zeek"
    ##################
    # Public library #
    ##################
    substituteInPlace $out/library/__load__.zeek \
    --replace "packages/domain-tld" "${hardenedlinux-zeek-scripts-sources.zeek-domain-tld.src}/scripts"

    ####################
    # protocols -> DNS #
    ####################
    substituteInPlace $out/protocols/dns/__load__.zeek \
    --replace "packages/known-hosts-with-dns" "${hardenedlinux-zeek-scripts-sources.zeek-known-hosts-with-dns.src}/scripts"
    ## feeds -> top-1m (replace to nix/store/<path>)
    substituteInPlace $out/protocols/dns/alexa/alexa_validation.zeek \
    --replace "top-1m.txt" "$out/protocols/dns/alexa/top-1m.txt"

    ## feeds -> dynamic_dns (replace to nix/store/<path>)
    substituteInPlace $out/protocols/dns/dyndns.zeek \
    --replace "dynamic_dns.txt" "$out/protocols/dns/dynamic_dns.txt"

    ###########
    # Tunnels #
    ###########
    substituteInPlace $out/tunnels/zeek-kafka.zeek \
    --replace "/usr/local/zeek/lib/zeek/plugins/" "${zeek-release}/lib/zeek/plugins/"


    runHook postInstall
  '';
}
