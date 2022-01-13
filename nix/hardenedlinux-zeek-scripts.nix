{ stdenvNoCC, lib, ripgrep, zeek-release, hardenedlinux-zeek-scripts-sources }:
let
  loadScripts = lib.concatStringsSep "\n" (map (f: "@load ${hardenedlinux-zeek-scripts-sources.${f}.src}/scripts") scripts);
  scripts = [
    "ja3"
    # TODO: fix
    # "top-dns"
    # "dns-tunnels"
    "dns-axfr"
    "scan-NG"
    "sip-attacks"
  ];
in
stdenvNoCC.mkDerivation rec {
  src = ../scripts;
  name = "hardenedlinux-zeek-script";
  phases = [ "installPhase" ];
  buildInputs = [ zeek-release ripgrep ];
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
    for file in $(rg -l -- "packages/domain-tld" $out); do
    substituteInPlace $file \
    --replace "packages/domain-tld" "${hardenedlinux-zeek-scripts-sources.zeek-domain-tld.src}/scripts"
    done
    ############################
    # zeek-sumstats-counttable #
    ############################
    for file in $(rg -l -- "packages/zeek-sumstats-counttable" $out); do
    substituteInPlace $file \
    --replace "packages/zeek-sumstats-counttable" "${hardenedlinux-zeek-scripts-sources.zeek-sumstats-counttable.src}"
    done
    #############################
    # zeek-known-hosts-with-dns #
    #############################
    for file in $(rg -l -- "packages/known-hosts-with-dns" $out); do
    substituteInPlace $file \
    --replace "packages/known-hosts-with-dns" "${hardenedlinux-zeek-scripts-sources.zeek-known-hosts-with-dns.src}/scripts"
    done
    ####################
    # protocols -> DNS #
    ####################
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
