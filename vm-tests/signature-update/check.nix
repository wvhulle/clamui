{ machine, ... }:
{
  name = "lazaret-signature-update";

  enableOCR = true;

  nodes.machine = machine;

  testScript = builtins.readFile ../shared/desktop_session.py + builtins.readFile ./check.py;
}
