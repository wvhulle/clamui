{
  pkgs,
  xtask,
  xtaskStatic,
  rustToolchain,
}:
let
  inherit (pkgs) lib;

  wrapXtaskTask =
    taskXtask:
    {
      name,
      taskArgs ? [ name ],
      runtimeInputs ? [ ],
      wrapperArgs ? [ ],
    }:
    pkgs.runCommand name
      {
        nativeBuildInputs = [ pkgs.makeBinaryWrapper ];
        meta.mainProgram = name;
      }
      ''
        makeWrapper ${lib.getExe taskXtask} $out/bin/${name} \
          ${lib.concatMapStringsSep " " (taskArg: "--add-flag ${lib.escapeShellArg taskArg}") taskArgs} \
          ${lib.optionalString (runtimeInputs != [ ]) "--prefix PATH : ${lib.makeBinPath runtimeInputs}"} \
          ${lib.escapeShellArgs wrapperArgs}
      '';

  xtaskTask = wrapXtaskTask xtask;

  releasePlzTask =
    subcommand:
    xtaskTask {
      name = subcommand;
      taskArgs = [
        "release-plz"
        subcommand
      ];
      runtimeInputs = [
        rustToolchain
        pkgs.release-plz
        pkgs.gitMinimal
      ];
    };
in
{
  release = releasePlzTask "release";
  release-pr = releasePlzTask "release-pr";
  upload-release-assets = xtaskTask {
    name = "upload-release-assets";
    runtimeInputs = [
      pkgs.tea
      pkgs.coreutils
    ];
  };
  prepare-ci-tools = wrapXtaskTask xtaskStatic { name = "prepare-ci-tools"; };
  download-tools = xtaskTask { name = "download-tools"; };
  check-commits = xtaskTask {
    name = "check-commits";
    runtimeInputs = [
      pkgs.convco
      pkgs.gitMinimal
    ];
  };
  open-dependency-update-pr = xtaskTask {
    name = "open-dependency-update-pr";
    runtimeInputs = [
      rustToolchain
      pkgs.gitMinimal
      pkgs.nix
      pkgs.tea
    ];
  };
}
