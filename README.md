# mvd2info

A command-line tool that extracts metadata from Quake 2 MVD2 (Multi-View Demo) files recorded by [Q2Pro](https://github.com/skullernet/q2pro) with [OpenTDM](https://github.com/packetflinger/opentdm) game mod.

Inspect any `.mvd2` demo file to see the map, server, players, teams, final scores, individual stats, spectators, kill log, and chat — without launching the game.

## Requirements

- Python 3.8 or newer

That's it. No pip installs, no compilation, no game engine required.

## Usage

```bash
# Basic — print everything to terminal
python3 mvd2info.py demo.mvd2

# JSON output
python3 mvd2info.py demo.mvd2 --json

# Save to file
python3 mvd2info.py demo.mvd2 -o result.txt
python3 mvd2info.py demo.mvd2 --json -o match.json

# Hide kill log and/or chat
python3 mvd2info.py demo.mvd2 --no-kills
python3 mvd2info.py demo.mvd2 --no-chat
python3 mvd2info.py demo.mvd2 --no-kills --no-chat
```

### Renaming demos

Automatically rename demo files to include team rosters and final scores:

```bash
# Preview what would be renamed (no files changed)
python3 mvd2info.py PFDE1_20260101-222222_q2duel1.mvd2 --rename --dry-run

# Rename a single file
python3 mvd2info.py PFDE1_20260101-222222_q2duel1.mvd2 --rename

# Rename all demos in a folder
python3 mvd2info.py /path/to/mvd/ --rename --dry-run    # preview first
python3 mvd2info.py /path/to/mvd/ --rename               # then apply
```

**Filename format:** `SERVER_DATETIME_team1players_score_VS_score_team2players_MAP.mvd2`

Team order follows Home/Away from the server, regardless of who won.

**Safety features:**
- `--dry-run` — preview all changes before applying
- Files already containing `_VS_` are skipped (already renamed)
- Files with non-standard names are skipped with a notice
- Special characters in player names (`[]()!@#` etc.) are replaced with `_`

On Windows, use `python` instead of `python3`:

```
python mvd2info.py demo.mvd2
```

### Command-line options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON instead of formatted text |
| `-o`, `--output FILE` | Write output to a file |
| `--no-kills` | Omit the kill log from output |
| `--no-chat` | Omit the chat log from output |
| `--rename` | Rename file(s) with match metadata injected into filename |
| `--dry-run` | Preview renames without changing any files (use with `--rename`) |

### JSON output structure

```json
{
  "file": {
    "name": "demo.mvd2",
    "size": 1465023,
    "protocol": 37,
    "version": 2010,
    "total_messages": 6202
  },
  "server": {
    "name": "Q2TR.COM ~ OpenTDM ~ Turkiye #2",
    "mod": "opentdm",
    "map": "q2dm1",
    "map_display_name": "The Edge",
    "date": "2026-02-10 22:29"
  },
  "teams": {
    "home": {
      "name": "Home",
      "score": 28,
      "players": [
        { "name": "Real", "frags": 16, "deaths": 16, "net": 0, "ping": 29 },
        { "name": "froggy", "frags": 8, "deaths": 16, "net": -7, "ping": 16 },
        { "name": "Launcher", "frags": 4, "deaths": 23, "net": -17, "ping": 32 }
      ]
    },
    "away": {
      "name": "Away",
      "score": 50,
      "players": [
        { "name": "Hidekuti", "frags": 26, "deaths": 5, "net": 21, "ping": 17 },
        { "name": "ToSCaNo", "frags": 20, "deaths": 11, "net": 10, "ping": 17 },
        { "name": "5himmy", "frags": 4, "deaths": 17, "net": -13, "ping": 1 }
      ]
    }
  },
  "match_result": {
    "winner_team": "Away",
    "winner_names": ["5himmy", "ToSCaNo", "Hidekuti"],
    "winner_score": 50,
    "loser_team": "Home",
    "loser_names": ["Real", "Launcher", "froggy"],
    "loser_score": 28,
    "end_trigger": ""
  },
  "spectators": [
    { "name": "yhyrs", "ping": 21, "chase_target": "Hidekuti" },
    { "name": "SWoRD", "ping": 11, "chase_target": "Hidekuti" },
    { "name": "NeO[GTT]", "ping": 32, "chase_target": "" }
  ],
  "kill_log": ["..."],
  "chat_log": ["..."]
}
```

## Credits

Built for the Quake 2 community. MVD2 format created by [Andrey "skuller" Nazarov](https://github.com/skullernet/q2pro) for Q2Pro. OpenTDM game mod by [packetflinger](https://github.com/packetflinger/opentdm).
