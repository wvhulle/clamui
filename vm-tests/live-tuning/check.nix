{ machine, ... }:
{
  name = "lazaret-live-tuning";

  enableOCR = true;

  nodes.machine = machine;

  testScript = builtins.readFile ../shared/desktop_session.py + builtins.readFile ./check.py;
}
