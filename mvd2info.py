#!/usr/bin/env python3
import struct
import re
import json
import sys
import os
import glob
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Filename Helpers ─────────────────────────────────────────────────────────

# Date pattern in original filenames: YYYYMMDD-HHMMSS
_DATE_RE = re.compile(r'^(\d{8}-\d{6})$')

# Characters allowed in filenames — everything else becomes _
_SAFE_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.')


def sanitize_name(name: str) -> str:
    """Sanitize a player name for use in a filename.
    Keeps only letters, digits, hyphen, dot. Everything else → underscore.
    Collapses multiple underscores into one."""
    out = []
    for c in name:
        if c in _SAFE_CHARS:
            out.append(c)
        else:
            out.append('_')
    result = ''.join(out)
    result = re.sub(r'_+', '_', result)
    return result.strip('_')


def parse_original_filename(filename: str):
    """Parse SERVER_DATETIME_MAP from an original MVD2 filename.
    Returns (server, datetime, map) or None if format doesn't match."""
    # Strip extension
    base = filename
    if base.lower().endswith('.mvd2'):
        base = base[:-5]

    parts = base.split('_')
    # Find the part matching YYYYMMDD-HHMMSS
    date_idx = None
    for i, part in enumerate(parts):
        if _DATE_RE.match(part):
            date_idx = i
            break

    if date_idx is None:
        return None

    server = '_'.join(parts[:date_idx])
    datetime_str = parts[date_idx]
    map_name = '_'.join(parts[date_idx + 1:])

    if not server or not map_name:
        return None

    return server, datetime_str, map_name


# ─── MVD2 Protocol Constants ─────────────────────────────────────────────────

MVD2_MAGIC = b'MVD2'

# MVD opcodes (empirically confirmed from real demo files)
MVD_NOP = 1
MVD_SERVERDATA = 4
MVD_CONFIGSTRING = 5
MVD_FRAME = 6
MVD_UNICAST = 8
MVD_UNICAST_R = 9
MVD_MULTICAST_ALL = 10
MVD_MULTICAST_PVS = 11
MVD_MULTICAST_PHS = 12
MVD_MULTICAST_ALL_R = 13
MVD_MULTICAST_PVS_R = 14
MVD_MULTICAST_PHS_R = 15
MVD_SOUND = 16
MVD_PRINT = 17

SVCMD_BITS = 5
SVCMD_MASK = (1 << SVCMD_BITS) - 1

# Q2 svc sub-commands (inside unicast/multicast payloads)
SVC_LAYOUT = 4
SVC_PRINT = 10
SVC_CONFIGSTRING = 13

# Configstring indices (old/standard Q2 remap — used when no EXTLIMITS)
CS_NAME = 0           # Map display name
CS_CDTRACK = 1
CS_SKY = 2
CS_AIRACCEL = 29
CS_MAXCLIENTS = 30
CS_MAPCHECKSUM = 31
CS_MODELS = 32        # models start here; [models+1] = map BSP path
CS_PLAYERSKINS = 1312 # player skins: "Name\model/skin"
CS_GENERAL = 1568     # general-purpose strings (team names, timer, etc.)
CS_GENERAL2 = 1824    # second general block (team assignments in OpenTDM)
MAX_CONFIGSTRINGS_OLD = 2080


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class PlayerInfo:
    slot: int
    name: str
    skin: str = ""
    team: str = ""           # "Home", "Away", or empty
    frags: Optional[int] = None
    deaths: Optional[int] = None
    net: Optional[int] = None
    ping: Optional[int] = None
    is_spectator: bool = False
    chase_target: str = ""   # who the spectator is watching

@dataclass
class MatchResult:
    winner_team: str = ""
    winner_names: list = field(default_factory=list)
    winner_score: int = 0
    loser_team: str = ""
    loser_names: list = field(default_factory=list)
    loser_score: int = 0
    end_trigger: str = ""    # "Timelimit", "Fraglimit", etc.

@dataclass
class DemoMetadata:
    filename: str = ""
    filesize: int = 0
    # Protocol
    protocol_version: int = 0
    minor_version: int = 0
    gamedir: str = ""
    dummy_client: int = -1
    # Map / Server
    map_name: str = ""
    map_display_name: str = ""
    server_name: str = ""
    # Teams
    team_home_name: str = "Home"
    team_away_name: str = "Away"
    team_home_score: Optional[int] = None
    team_away_score: Optional[int] = None
    # Players
    players: list = field(default_factory=list)
    spectators: list = field(default_factory=list)
    # Match
    match_result: Optional[MatchResult] = None
    match_date: str = ""
    match_duration_timer: str = ""
    match_state: str = ""    # Warmup, Countdown, Match, etc.
    # Logs
    kill_log: list = field(default_factory=list)
    chat_log: list = field(default_factory=list)
    # Raw
    total_messages: int = 0


# ─── Binary Reader ────────────────────────────────────────────────────────────

class BinaryReader:
    """Lightweight binary reader for MVD2 message payloads."""

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.pos = offset

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise EOFError("Read past end of data")
        val = self.data[self.pos]
        self.pos += 1
        return val

    def read_word(self) -> int:
        """Read uint16 little-endian."""
        if self.pos + 2 > len(self.data):
            raise EOFError("Read past end of data")
        val = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_short(self) -> int:
        """Read int16 little-endian."""
        if self.pos + 2 > len(self.data):
            raise EOFError("Read past end of data")
        val = struct.unpack_from('<h', self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_long(self) -> int:
        """Read int32 little-endian."""
        if self.pos + 4 > len(self.data):
            raise EOFError("Read past end of data")
        val = struct.unpack_from('<i', self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_string(self) -> str:
        """Read null-terminated string."""
        end = self.data.index(0, self.pos)
        s = self.data[self.pos:end].decode('ascii', errors='replace')
        self.pos = end + 1
        return s

    def skip(self, n: int):
        self.pos += n


# ─── MVD2 Parser ─────────────────────────────────────────────────────────────

class MVD2Inspector:
    """Parses an MVD2 demo file and extracts all metadata."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = b''
        self.configstrings: dict[int, str] = {}
        self.meta = DemoMetadata()
        self.meta.filename = os.path.basename(filepath)

        # Internal tracking
        self._prints: list[tuple[str, int, str]] = []  # (source, level, text)
        self._layouts: list[str] = []
        self._kill_messages: list[str] = []
        self._chat_messages: list[str] = []
        self._match_ended_string: str = ""

    def inspect(self) -> DemoMetadata:
        """Main entry point — parse file and return metadata."""
        with open(self.filepath, 'rb') as f:
            self.data = f.read()
        self.meta.filesize = len(self.data)

        if not self._validate_magic():
            raise ValueError("Not a valid MVD2 file (bad magic header)")

        self._parse_all_messages()
        self._extract_map_info()
        self._extract_players_and_teams()
        self._extract_scores_from_layouts()
        self._extract_match_result()
        self._extract_server_info()
        self._extract_match_timing()
        self._classify_kills_and_chat()

        return self.meta

    # ── File Validation ───────────────────────────────────────────────────

    def _validate_magic(self) -> bool:
        return len(self.data) >= 4 and self.data[:4] == MVD2_MAGIC

    # ── Message Loop ──────────────────────────────────────────────────────

    def _parse_all_messages(self):
        """Walk through every message in the file."""
        pos = 4  # skip magic
        msg_count = 0
        first_message = True

        while pos + 2 <= len(self.data):
            msglen = struct.unpack_from('<H', self.data, pos)[0]
            pos += 2
            if msglen == 0 or pos + msglen > len(self.data):
                break
            msg = self.data[pos:pos + msglen]
            pos += msglen
            msg_count += 1

            if first_message:
                self._parse_gamestate(msg)
                first_message = False
                continue

            self._parse_message_commands(msg, msg_count)

        self.meta.total_messages = msg_count

    # ── Gamestate (First Message) ─────────────────────────────────────────

    def _parse_gamestate(self, msg: bytes):
        """Parse the serverdata + configstrings from the first message."""
        r = BinaryReader(msg)

        # Command byte
        cmd_byte = r.read_byte()
        cmd = cmd_byte & SVCMD_MASK
        extrabits = cmd_byte >> SVCMD_BITS

        if cmd != MVD_SERVERDATA:
            raise ValueError(f"First message is not serverdata (cmd={cmd})")

        # Protocol fields
        self.meta.protocol_version = r.read_long()   # PROTOCOL_VERSION_MVD (37)
        self.meta.minor_version = r.read_word()       # minor version (e.g. 2010)
        # Flags come from extrabits in the old protocol path
        # (version >= EXTENDED_LIMITS_2 would use a separate word, but
        #  our demo uses the old path based on byte analysis)
        flags = extrabits

        server_count = r.read_long()
        self.meta.gamedir = r.read_string()
        self.meta.dummy_client = r.read_short()

        # Parse configstrings until terminator
        while r.remaining() > 2:
            index = r.read_word()
            if index >= MAX_CONFIGSTRINGS_OLD:
                break  # terminator
            try:
                string = r.read_string()
                self.configstrings[index] = string
            except (ValueError, IndexError):
                break

    # ── Subsequent Messages ───────────────────────────────────────────────

    def _parse_message_commands(self, msg: bytes, msg_num: int):
        """Parse commands within a single message packet."""
        r = BinaryReader(msg)

        while r.remaining() > 0:
            try:
                cmd_byte = r.read_byte()
            except EOFError:
                break

            cmd = cmd_byte & SVCMD_MASK
            extrabits = cmd_byte >> SVCMD_BITS

            try:
                if cmd == MVD_SERVERDATA:
                    # Re-gamestate (map change) — skip rest
                    break

                elif cmd == MVD_CONFIGSTRING:
                    self._parse_configstring_update(r)

                elif cmd == MVD_FRAME:
                    # Delta-encoded frame data — skip rest of message
                    break

                elif cmd in (MVD_UNICAST, MVD_UNICAST_R):
                    self._parse_unicast(r, extrabits)

                elif cmd in (MVD_MULTICAST_ALL, MVD_MULTICAST_PVS,
                             MVD_MULTICAST_PHS, MVD_MULTICAST_ALL_R,
                             MVD_MULTICAST_PVS_R, MVD_MULTICAST_PHS_R):
                    self._parse_multicast(r, cmd, extrabits)

                elif cmd == MVD_SOUND:
                    self._parse_sound(r, extrabits)

                elif cmd == MVD_PRINT:
                    self._parse_print(r)

                elif cmd == MVD_NOP:
                    pass

                else:
                    # Unknown command — skip rest of message to be safe
                    break

            except (EOFError, ValueError, IndexError, struct.error):
                break

    def _parse_configstring_update(self, r: BinaryReader):
        """Parse a configstring change command."""
        index = r.read_word()
        string = r.read_string()
        self.configstrings[index] = string

    def _parse_unicast(self, r: BinaryReader, extrabits: int):
        """Parse unicast/unicast_r — extract prints from sub-payload."""
        length = (extrabits << 8) | r.read_byte()
        clientnum = r.read_byte()
        sub_end = r.pos + length

        # Only parse sub-payload if sent to the dummy client
        if clientnum == self.meta.dummy_client and length > 1 and r.pos < sub_end:
            subcmd = r.data[r.pos]
            if subcmd == SVC_PRINT and r.pos + 2 < sub_end:
                r.skip(1)  # subcmd byte
                level = r.read_byte()
                try:
                    text = r.read_string()
                    self._prints.append(('unicast', level, text))
                except (ValueError, IndexError):
                    pass
                # Position might not be at sub_end, fix it
                r.pos = sub_end
                return

        r.pos = sub_end

    def _parse_multicast(self, r: BinaryReader, cmd: int, extrabits: int):
        """Parse multicast — skip the sub-payload."""
        length = (extrabits << 8) | r.read_byte()
        # PVS/PHS variants carry a leafnum (uint16)
        if cmd in (MVD_MULTICAST_PVS, MVD_MULTICAST_PHS,
                   MVD_MULTICAST_PVS_R, MVD_MULTICAST_PHS_R):
            r.skip(2)  # leafnum
        r.skip(length)

    def _parse_sound(self, r: BinaryReader, extrabits: int):
        """Parse sound command — variable length, skip it."""
        # Sound encoding: flags in extrabits determine which fields follow
        # Minimum: 1 byte (sound index) + variable entity/position data
        # Rather than fully decode, consume based on flags
        flags = extrabits
        r.read_byte()  # sound index
        if flags & 1:  # volume
            r.read_byte()
        if flags & 2:  # attenuation
            r.read_byte()
        if flags & 8:  # timeofs
            r.read_byte()
        # Entity + channel encoding
        val = r.read_word()
        if flags & 16:  # positioned
            # 3 × int16 for position
            r.skip(6)

    def _parse_print(self, r: BinaryReader):
        """Parse a broadcast print message."""
        level = r.read_byte()
        text = r.read_string()
        self._prints.append(('broadcast', level, text))

    # ── Metadata Extraction ───────────────────────────────────────────────

    def _extract_map_info(self):
        """Extract map name from configstrings."""
        # CS[33] = models+1 = "maps/q2dm1.bsp"
        bsp_path = self.configstrings.get(CS_MODELS + 1, "")
        if bsp_path.startswith("maps/") and bsp_path.endswith(".bsp"):
            self.meta.map_name = bsp_path[5:-4]  # strip maps/ and .bsp
        elif bsp_path:
            self.meta.map_name = bsp_path

        # CS[0] = map display name
        self.meta.map_display_name = self.configstrings.get(CS_NAME, "")

    def _extract_players_and_teams(self):
        """Build player list from playerskin and general configstrings."""
        maxclients_str = self.configstrings.get(CS_MAXCLIENTS, "20")
        try:
            maxclients = int(maxclients_str)
        except ValueError:
            maxclients = 20

        # Parse CS[1824+] for team assignments: "PlayerName (TeamName)"
        team_assignments: dict[str, str] = {}  # name -> team
        for i in range(CS_GENERAL2, CS_GENERAL2 + maxclients):
            s = self.configstrings.get(i, "").strip()
            if not s:
                continue
            m = re.match(r'^(.+?)\s*\((\w+)\)$', s)
            if m:
                team_assignments[m.group(1)] = m.group(2)

        # Parse playerskins CS[1312..1312+maxclients]
        all_players: dict[int, PlayerInfo] = {}
        for i in range(CS_PLAYERSKINS, CS_PLAYERSKINS + maxclients):
            s = self.configstrings.get(i, "").strip()
            if not s:
                continue
            slot = i - CS_PLAYERSKINS

            parts = s.split('\\', 1)
            name = parts[0]
            skin = parts[1] if len(parts) > 1 else ""

            player = PlayerInfo(
                slot=slot,
                name=name,
                skin=skin,
                team=team_assignments.get(name, ""),
            )
            all_players[slot] = player

        # Dummy client is the MVD observer (always a spectator)
        dummy = self.meta.dummy_client

        # We'll classify spectators vs players after extracting scores
        # from the scoreboard layout. For now, store all.
        self._all_players = all_players

    def _extract_scores_from_layouts(self):
        """Extract team and individual scores by scanning raw binary for
        scoreboard layout strings embedded in the file."""
        # Decode entire file as ASCII (replacing non-printable)
        raw = self.data.decode('ascii', errors='replace')

        # ── Team Scores ──
        # Pattern: string "Home              28" / string "Away              50"
        # In 1v1: string "Launcher           4" / string "5himmy             2"
        # The two team lines always follow the "Team          Frags" header
        team_pattern = re.compile(
            r'Team\s+Frags"\s*'
            r'yv\s+\d+\s+string\s+"(.+?)\s+(\d+)"\s*'
            r'yv\s+\d+\s+string\s+"(.+?)\s+(\d+)"'
        )
        team_matches = list(team_pattern.finditer(raw))
        if team_matches:
            last = team_matches[-1]
            team1_name = last.group(1).strip()
            team1_score = int(last.group(2))
            team2_name = last.group(3).strip()
            team2_score = int(last.group(4))

            # Detect if team names are player names (1v1) or Home/Away (TDM)
            if team1_name == self.meta.team_home_name.strip():
                self.meta.team_home_score = team1_score
                self.meta.team_away_score = team2_score
            elif team1_name == self.meta.team_away_name.strip():
                self.meta.team_away_score = team1_score
                self.meta.team_home_score = team2_score
            else:
                # 1v1 mode — team names ARE player names
                self.meta.team_home_name = team1_name
                self.meta.team_home_score = team1_score
                self.meta.team_away_name = team2_name
                self.meta.team_away_score = team2_score
                # Remap player team assignments to match
                for p in self._all_players.values():
                    if p.name == team1_name:
                        p.team = team1_name
                    elif p.name == team2_name:
                        p.team = team2_name

        # ── Match Date ──
        date_pattern = re.compile(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\]')
        date_matches = list(date_pattern.finditer(raw))
        if date_matches:
            self.meta.match_date = date_matches[-1].group(1)

        # ── Individual Scores ──
        # Pattern: string "PlayerName           16   16   0   29"
        # These follow the "Name            Frags Dths Net Ping" header
        # Each player line: name padded to ~20 chars, then frags/deaths/net/ping
        player_score_pattern = re.compile(
            r'string\s+"([A-Za-z0-9\[\]_\-\.]+)\s+'
            r'(-?\d+)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)"'
        )

        # Find the last scoreboard block (after the last "Name.*Frags.*Dths")
        header_idx = raw.rfind('Name            Frags Dths Net Ping')
        if header_idx != -1:
            # Search in the region after the last header (within ~1000 chars)
            search_region = raw[header_idx:header_idx + 1500]
            score_matches = player_score_pattern.findall(search_region)

            scored_names = set()
            for name, frags, deaths, net, ping in score_matches:
                name = name.strip()
                if name in scored_names:
                    continue  # avoid duplicate from the two-column layout
                scored_names.add(name)

                # Find matching player
                for slot, player in self._all_players.items():
                    if player.name == name:
                        player.frags = int(frags)
                        player.deaths = int(deaths)
                        player.net = int(net)
                        player.ping = int(ping)
                        break

        # ── Spectators ──
        # Pattern: string "yhyrs:21->Hidekuti    "
        # Appears after " Spectators" in the layout
        spec_idx = raw.rfind(' Spectators')
        spectator_infos: list[PlayerInfo] = []
        if spec_idx != -1:
            spec_region = raw[spec_idx:spec_idx + 500]
            # Match: "Name:ping->Target    " or "Name:ping"
            spec_pattern = re.compile(
                r'string\s+"([A-Za-z0-9\[\]_\-\.]+):(\d+)'
                r'(?:->([A-Za-z0-9\[\]_\-\.]+))?\s*"'
            )
            for m in spec_pattern.finditer(spec_region):
                spec_name = m.group(1)
                spec_ping = int(m.group(2))
                chase = m.group(3) or ""
                spectator_infos.append(PlayerInfo(
                    slot=-1,
                    name=spec_name,
                    ping=spec_ping,
                    is_spectator=True,
                    chase_target=chase,
                ))

        # ── Classify Players vs Spectators ──
        spec_names = {s.name for s in spectator_infos}
        dummy = self.meta.dummy_client

        # Collect names of players who have scores (from scoreboard)
        scored_player_names = set()
        for slot, player in self._all_players.items():
            if player.frags is not None and player.team:
                scored_player_names.add(player.name)

        seen_player_names = set()
        for slot, player in self._all_players.items():
            if slot == dummy:
                continue  # skip MVD dummy
            if player.name in spec_names:
                continue  # already captured in spectator_infos
            if player.name in seen_player_names:
                continue  # skip duplicate slots (common in 1v1)

            if player.team and player.frags is not None:
                self.meta.players.append(player)
                seen_player_names.add(player.name)
            elif player.frags is not None and player.name not in scored_player_names:
                # Has score but no team assignment — still a player
                self.meta.players.append(player)
                seen_player_names.add(player.name)
            elif player.name not in scored_player_names:
                # No score, no team — likely spectator or late joiner
                # But don't add if they're already a known player
                spectator_infos.append(PlayerInfo(
                    slot=slot,
                    name=player.name,
                    is_spectator=True,
                ))

        # Sort players: by team then by frags descending
        home = self.meta.team_home_name
        self.meta.players.sort(
            key=lambda p: (0 if p.team == home else 1, -(p.frags or 0))
        )

        # Deduplicate spectators by name
        seen_spec = set()
        unique_specs = []
        for s in spectator_infos:
            if s.name not in seen_spec:
                seen_spec.add(s.name)
                unique_specs.append(s)
        self.meta.spectators = unique_specs

    def _extract_match_result(self):
        """Extract match result from prints or raw binary search.

        OpenTDM uses (at least) two different result formats:
          Format A: "MATCH_ENDED: player1, player2 wins X to Y against player3, player4"
          Format B: "Timelimit hit. Match ended." + "Home wins, 63 to 15."
                    or "Fraglimit hit." + "Away wins, 50 to 28."
        """
        raw = self.data.decode('ascii', errors='replace')
        result = MatchResult()
        found = False

        # ── Format A: "MATCH_ENDED: names wins X to Y against names" ─────
        me_pattern = re.compile(
            r'MATCH_ENDED:\s*(.+?)\s+wins\s+(\d+)\s+to\s+(\d+)\s+against\s+(.+?)[\x00\r\n]',
            re.IGNORECASE
        )
        m = me_pattern.search(raw)
        if m:
            winner_names = [n.strip() for n in m.group(1).split(',')]
            winner_score = int(m.group(2))
            loser_score = int(m.group(3))
            loser_names = [n.strip() for n in m.group(4).split(',')]

            # Determine team names from player roster
            for p in self.meta.players:
                if p.name in winner_names and p.team:
                    result.winner_team = p.team
                elif p.name in loser_names and p.team:
                    result.loser_team = p.team

            result.winner_names = winner_names
            result.winner_score = winner_score
            result.loser_names = loser_names
            result.loser_score = loser_score
            found = True

        # ── Format B: "TeamName wins, X to Y." (broadcast print) ─────────
        if not found:
            for src, level, text in self._prints:
                clean = self._strip_q2_colors(text).strip()
                # Match: "Home wins, 63 to 15." or "Away wins, 50 to 28."
                win_match = re.match(
                    r'^(\w+)\s+wins,\s+(\d+)\s+to\s+(\d+)\.',
                    clean
                )
                if win_match:
                    winner_team = win_match.group(1)
                    winner_score = int(win_match.group(2))
                    loser_score = int(win_match.group(3))

                    # Determine the loser team
                    if winner_team == self.meta.team_home_name:
                        loser_team = self.meta.team_away_name
                    elif winner_team == self.meta.team_away_name:
                        loser_team = self.meta.team_home_name
                    else:
                        loser_team = ""

                    # Collect player names per team
                    winner_names = [p.name for p in self.meta.players if p.team == winner_team]
                    loser_names = [p.name for p in self.meta.players if p.team == loser_team]

                    result.winner_team = winner_team
                    result.winner_score = winner_score
                    result.winner_names = winner_names
                    result.loser_team = loser_team
                    result.loser_score = loser_score
                    result.loser_names = loser_names
                    found = True
                    break

        # ── End trigger: Timelimit / Fraglimit ────────────────────────────
        for src, level, text in self._prints:
            clean = self._strip_q2_colors(text).strip()
            if 'Timelimit hit' in clean:
                result.end_trigger = "Timelimit"
            elif 'Fraglimit hit' in clean:
                result.end_trigger = "Fraglimit"

        if found or result.end_trigger:
            self.meta.match_result = result

    def _extract_server_info(self):
        """Extract server name from layout footer."""
        raw = self.data.decode('ascii', errors='replace')
        # Pattern: string2 "Q2TR.COM ~ OpenTDM ~ Turkiye #2"
        srv_pattern = re.compile(r'yb\s+-\d+\s+string2?\s+"([^"]+)"')
        # The server name appears near "yb -37" (bottom of screen)
        for m in srv_pattern.finditer(raw):
            candidate = m.group(1).strip()
            # Server name is usually the one with ~ or longer text at bottom
            if '~' in candidate or len(candidate) > 20:
                self.meta.server_name = candidate
                break

        # Team names from CS[1568] and CS[1569]
        home_name = self.configstrings.get(CS_GENERAL, "").strip()
        away_name = self.configstrings.get(CS_GENERAL + 1, "").strip()
        if home_name:
            self.meta.team_home_name = home_name
        if away_name:
            self.meta.team_away_name = away_name

    def _extract_match_timing(self):
        """Extract match state and timer from configstrings."""
        self.meta.match_state = self.configstrings.get(CS_GENERAL + 6, "")  # 1574
        timer = self.configstrings.get(CS_GENERAL + 4, "").strip()  # 1572
        if timer:
            self.meta.match_duration_timer = timer

    def _classify_kills_and_chat(self):
        """Separate kill messages and chat from prints."""
        for src, level, text in self._prints:
            clean = self._strip_q2_colors(text).strip()
            if not clean or len(clean) < 3:
                continue

            # Level 1 = obituary (kill messages) — broadcast only
            if level == 1 and src == 'broadcast':
                # Clean trailing garbage from Q2 high-bit color sequences
                # Kill messages end with \n, strip anything after
                clean = clean.split('\n')[0].strip()
                # Remove any remaining Q2 color artifacts (}|~ etc. runs at end)
                clean = re.sub(r'[}\|~\x00-\x1f]{3,}.*$', '', clean).strip()
                if clean:
                    self.meta.kill_log.append(clean)

            # Unicast level 3 prints to dummy = player chat messages
            # Format: "PlayerName: message"
            if src == 'unicast' and level == 3:
                clean = clean.split('\n')[0].strip()
                if clean and ':' in clean:
                    self.meta.chat_log.append(clean)

            # Broadcast level 2 = game events (ready, countdown, etc.)
            # Broadcast level 3 = server messages (not player chat)

    @staticmethod
    def _strip_q2_colors(text: str) -> str:
        """Strip Quake 2 high-bit color codes from text."""
        return ''.join(
            chr(ord(c) & 0x7F) if ord(c) > 127 else c
            for c in text
        )

    # ── Output Formatting ─────────────────────────────────────────────────

    def format_text(self) -> str:
        """Format metadata as human-readable text."""
        m = self.meta
        lines = []
        sep = "─" * 60

        lines.append(sep)
        lines.append(f"  mvd2info — Quake 2 Demo Inspector")
        lines.append(sep)
        lines.append(f"  File:       {m.filename} ({m.filesize:,} bytes)")
        lines.append(f"  Protocol:   {m.protocol_version} (v{m.minor_version})")
        lines.append(f"  Messages:   {m.total_messages:,}")
        lines.append(sep)
        lines.append(f"  Server:     {m.server_name}")
        lines.append(f"  Mod:        {m.gamedir}")
        lines.append(f"  Map:        {m.map_name} ({m.map_display_name})")
        if m.match_date:
            lines.append(f"  Date:       {m.match_date}")
        lines.append(sep)

        # Teams and Scores
        lines.append(f"  TEAMS & SCORES")
        lines.append(f"")
        h_score = m.team_home_score if m.team_home_score is not None else "?"
        a_score = m.team_away_score if m.team_away_score is not None else "?"
        lines.append(f"    {m.team_home_name:>20s}  {h_score:>3}  vs  {a_score:<3}  {m.team_away_name}")
        lines.append(f"")

        if m.match_result:
            mr = m.match_result
            winner_str = ', '.join(mr.winner_names)
            lines.append(f"  Result:     {winner_str} wins {mr.winner_score}-{mr.loser_score}")
            if mr.end_trigger:
                lines.append(f"  End:        {mr.end_trigger}")

        lines.append(sep)
        lines.append(f"  PLAYER STATISTICS")
        lines.append(f"")

        # Detect 1v1: team name == player name means team column is redundant
        is_duel = any(
            p.team == p.name for p in m.players if p.team
        )

        if is_duel:
            lines.append(f"    {'Name':<20s} {'Frags':>5s} {'Deaths':>6s} {'Net':>5s} {'Ping':>5s}")
            lines.append(f"    {'─'*20} {'─'*5} {'─'*6} {'─'*5} {'─'*5}")
        else:
            lines.append(f"    {'Name':<20s} {'Team':<6s} {'Frags':>5s} {'Deaths':>6s} {'Net':>5s} {'Ping':>5s}")
            lines.append(f"    {'─'*20} {'─'*6} {'─'*5} {'─'*6} {'─'*5} {'─'*5}")

        for p in m.players:
            frags = str(p.frags) if p.frags is not None else "-"
            deaths = str(p.deaths) if p.deaths is not None else "-"
            net = str(p.net) if p.net is not None else "-"
            ping = str(p.ping) if p.ping is not None else "-"
            if is_duel:
                lines.append(
                    f"    {p.name:<20s} {frags:>5s} {deaths:>6s} {net:>5s} {ping:>5s}"
                )
            else:
                lines.append(
                    f"    {p.name:<20s} {p.team:<6s} {frags:>5s} {deaths:>6s} {net:>5s} {ping:>5s}"
                )

        lines.append(sep)
        if m.spectators:
            lines.append(f"  SPECTATORS")
            lines.append(f"")
            for s in m.spectators:
                chase = f" -> {s.chase_target}" if s.chase_target else ""
                ping = f" (ping: {s.ping})" if s.ping is not None else ""
                lines.append(f"    {s.name}{chase}{ping}")
            lines.append(sep)

        if m.kill_log:
            lines.append(f"  KILL LOG ({len(m.kill_log)} kills)")
            lines.append(f"")
            for kill in m.kill_log:
                lines.append(f"    {kill}")
            lines.append(sep)

        if m.chat_log:
            lines.append(f"  CHAT LOG ({len(m.chat_log)} messages)")
            lines.append(f"")
            for msg in m.chat_log:
                lines.append(f"    {msg}")
            lines.append(sep)

        return '\n'.join(lines)

    def format_json(self) -> str:
        """Format metadata as JSON."""
        m = self.meta
        output = {
            "file": {
                "name": m.filename,
                "size": m.filesize,
                "protocol": m.protocol_version,
                "version": m.minor_version,
                "total_messages": m.total_messages,
            },
            "server": {
                "name": m.server_name,
                "mod": m.gamedir,
                "map": m.map_name,
                "map_display_name": m.map_display_name,
                "date": m.match_date,
            },
            "teams": {
                "home": {
                    "name": m.team_home_name,
                    "score": m.team_home_score,
                    "players": [
                        {
                            "name": p.name,
                            "frags": p.frags,
                            "deaths": p.deaths,
                            "net": p.net,
                            "ping": p.ping,
                        }
                        for p in m.players if p.team == "Home"
                    ],
                },
                "away": {
                    "name": m.team_away_name,
                    "score": m.team_away_score,
                    "players": [
                        {
                            "name": p.name,
                            "frags": p.frags,
                            "deaths": p.deaths,
                            "net": p.net,
                            "ping": p.ping,
                        }
                        for p in m.players if p.team == "Away"
                    ],
                },
            },
            "match_result": None,
            "spectators": [
                {
                    "name": s.name,
                    "ping": s.ping,
                    "chase_target": s.chase_target,
                }
                for s in m.spectators
            ],
            "kill_log": m.kill_log,
            "chat_log": m.chat_log,
        }

        if m.match_result:
            mr = m.match_result
            output["match_result"] = {
                "winner_team": mr.winner_team,
                "winner_names": mr.winner_names,
                "winner_score": mr.winner_score,
                "loser_team": mr.loser_team,
                "loser_names": mr.loser_names,
                "loser_score": mr.loser_score,
                "end_trigger": mr.end_trigger,
            }

        return json.dumps(output, indent=2, ensure_ascii=False)

    def generate_renamed_filename(self) -> Optional[str]:
        """Generate a new filename with team rosters and scores injected.

        Format: SERVER_DATETIME_team1players_score1_VS_score2_team2players_MAP.mvd2

        Returns None if the original filename doesn't match the expected format.
        """
        parsed = parse_original_filename(self.meta.filename)
        if parsed is None:
            return None

        server, datetime_str, map_name = parsed
        m = self.meta

        # Get home team players
        home_players = [p for p in m.players if p.team == m.team_home_name]
        away_players = [p for p in m.players if p.team == m.team_away_name]

        # If no team-based split worked, try home/away as first/second half
        if not home_players and not away_players and m.players:
            # Fallback: all players on one side (shouldn't happen, but safe)
            home_players = m.players
            away_players = []

        # Build name parts
        home_names = '_'.join(sanitize_name(p.name) for p in home_players) or 'unknown'
        away_names = '_'.join(sanitize_name(p.name) for p in away_players) or 'unknown'

        home_score = m.team_home_score if m.team_home_score is not None else 0
        away_score = m.team_away_score if m.team_away_score is not None else 0

        # Sanitize map name too (should be clean already, but just in case)
        safe_map = sanitize_name(map_name)

        new_name = (
            f"{server}_{datetime_str}_"
            f"{home_names}_{home_score}_VS_{away_score}_{away_names}_"
            f"{safe_map}.mvd2"
        )

        return new_name


# ─── Rename Functions ─────────────────────────────────────────────────────────

def rename_file(filepath: str, dry_run: bool = False) -> tuple[bool, str]:
    """Parse a single MVD2 file and rename it with match metadata.

    Returns (success, message) tuple.
    """
    filename = os.path.basename(filepath)
    dirpath = os.path.dirname(filepath) or '.'

    # Skip already-renamed files
    if '_VS_' in filename:
        return False, f"SKIP (already renamed): {filename}"

    # Check filename format
    parsed = parse_original_filename(filename)
    if parsed is None:
        return False, f"SKIP (non-standard name): {filename}"

    # Parse the demo
    try:
        inspector = MVD2Inspector(filepath)
        inspector.inspect()
    except Exception as e:
        return False, f"ERROR: {filename} — {e}"

    new_name = inspector.generate_renamed_filename()
    if new_name is None:
        return False, f"SKIP (could not generate name): {filename}"

    if new_name == filename:
        return False, f"SKIP (name unchanged): {filename}"

    new_path = os.path.join(dirpath, new_name)

    if dry_run:
        return True, f"  {filename}\n  → {new_name}"
    else:
        try:
            os.rename(filepath, new_path)
            return True, f"  {filename}\n  → {new_name}"
        except OSError as e:
            return False, f"ERROR renaming {filename}: {e}"


def rename_batch(path: str, dry_run: bool = False):
    """Rename a single file or all MVD2 files in a directory."""
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, '*.mvd2')))
        if not files:
            print(f"No .mvd2 files found in {path}")
            return
    else:
        print(f"Error: {path} is not a file or directory", file=sys.stderr)
        sys.exit(1)

    total = len(files)
    renamed = 0
    skipped = 0
    errors = 0

    if dry_run:
        print(f"DRY RUN — no files will be renamed\n")

    for i, filepath in enumerate(files, 1):
        prefix = f"[{i}/{total}]"
        success, message = rename_file(filepath, dry_run=dry_run)

        if success:
            renamed += 1
            print(f"{prefix} RENAME:")
            print(f"  {message}")
        elif message.startswith("SKIP"):
            skipped += 1
            print(f"{prefix} {message}")
        else:
            errors += 1
            print(f"{prefix} {message}")

    # Summary
    print(f"\nDone: {renamed} renamed, {skipped} skipped, {errors} errors (out of {total} files)")
    if dry_run and renamed > 0:
        print(f"Run without --dry-run to apply changes.")


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="mvd2info",
        description="mvd2info — Extract metadata from Q2Pro MVD2 demo files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s demo.mvd2                           Inspect a demo file
  %(prog)s demo.mvd2 --json                    Output as JSON
  %(prog)s demo.mvd2 --json -o match.json      Save JSON to file
  %(prog)s demo.mvd2 --no-kills --no-chat      Hide kill/chat logs

  %(prog)s demo.mvd2 --rename --dry-run        Preview rename
  %(prog)s demo.mvd2 --rename                  Rename single file
  %(prog)s /mvd/folder/ --rename --dry-run     Preview batch rename
  %(prog)s /mvd/folder/ --rename               Rename all demos in folder
        """
    )
    parser.add_argument("file", help="Path to .mvd2 file or directory of .mvd2 files")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--output", "-o", help="Write output to file instead of stdout")
    parser.add_argument("--no-kills", action="store_true", help="Omit kill log")
    parser.add_argument("--no-chat", action="store_true", help="Omit chat log")
    parser.add_argument("--rename", action="store_true",
                        help="Rename file(s) with match metadata "
                             "(SERVER_DATE_team1_score_VS_score_team2_MAP.mvd2)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview renames without changing any files (use with --rename)")

    args = parser.parse_args()

    # ── Rename mode ──
    if args.rename:
        rename_batch(args.file, dry_run=args.dry_run)
        return

    # ── Inspect mode ──
    if not os.path.isfile(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    try:
        inspector = MVD2Inspector(args.file)
        meta = inspector.inspect()

        if args.no_kills:
            meta.kill_log = []
        if args.no_chat:
            meta.chat_log = []

        if args.json:
            output = inspector.format_json()
        else:
            output = inspector.format_text()

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Output written to {args.output}")
        else:
            print(output)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing demo: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
