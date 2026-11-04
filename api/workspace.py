"""Users, sessions and each user's work: lists, account statuses, saved searches and the profile.

This is the app's only writable state; scan data lives in the read-only serving store (api/store.py).
The two are different workloads and get different engines: DuckDB for column scans over millions of
rows rebuilt per batch, a row store with transactions for small, frequent writes that must not be lost.

This deployment uses SQLite (WAL: many readers, one writer, ample for one API host and writes this
small). Production uses Postgres: several API instances, teams editing the same lists, backups and
point-in-time recovery. The queries are portable SQL (only the connection setup below is
SQLite-specific), and every row belongs to a workspace, so moving to Postgres is a change in this one
module and adding teams is a membership table.

  RECON_DB     SQLite file (default data/app/recon.db)
  RECON_USERS  name:hash pairs, comma-separated; make a hash with `python -m api.workspace hash`
"""
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.environ.get("RECON_DB", os.path.join(ROOT, "data", "app", "recon.db"))
SESSION_DAYS = 14
# a workspace is a person's (or, in production, a team's) sandbox; caps keep a public demo bounded
MAX_LISTS, MAX_LISTED, MAX_SEARCHES = 50, 20_000, 50
STATUSES = ("to_contact", "contacted", "meeting", "not_a_fit")
ID = re.compile(r"^[a-z][a-z0-9]{5,31}$")

SCHEMA = """
create table if not exists workspaces (
  id text primary key, name text not null, created text not null);
create table if not exists users (
  id text primary key, username text not null unique, password_hash text not null,
  workspace_id text not null references workspaces(id), created text not null);
create table if not exists sessions (
  token_hash text primary key, user_id text not null references users(id) on delete cascade,
  created text not null, expires text not null);
create table if not exists lists (
  id text primary key, workspace_id text not null references workspaces(id) on delete cascade,
  name text not null, created text not null);
create table if not exists list_items (
  list_id text not null references lists(id) on delete cascade, account_id text not null,
  added text not null, primary key (list_id, account_id));
create table if not exists account_status (
  workspace_id text not null references workspaces(id) on delete cascade, account_id text not null,
  status text not null, updated text not null, primary key (workspace_id, account_id));
create table if not exists saved_searches (
  id text primary key, workspace_id text not null references workspaces(id) on delete cascade,
  name text not null, filters text not null, profile text not null, created text not null,
  last_run text, last_run_at text, schedule text not null default 'daily');
create table if not exists profiles (
  workspace_id text primary key references workspaces(id) on delete cascade,
  data text not null, updated text not null);
create index if not exists lists_by_workspace on lists(workspace_id);
create index if not exists items_by_account on list_items(account_id);
create index if not exists searches_by_workspace on saved_searches(workspace_id);
"""


class LimitError(ValueError):
    """A workspace cap was reached (lists, listed accounts or saved searches)."""


def now():
    # microseconds, so rows made in the same second still sort in the order they were made
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def new_id(prefix):
    return prefix + secrets.token_hex(8)


# passwords --------------------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    # '.'-separated, not '$': Docker Compose would interpolate '$' in the .env this is kept in
    return f"scrypt.{salt.hex()}.{digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, digest = stored.split(".")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(got.hex(), digest)


class Workspace:
    def __init__(self, path=DB):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self._con().executescript(SCHEMA)  # idempotent; executescript manages its own transaction

    def _con(self):
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            con.row_factory = sqlite3.Row
            con.execute("pragma journal_mode = wal")
            con.execute("pragma foreign_keys = on")
            con.execute("pragma busy_timeout = 10000")
            self._local.con = con
        return con

    class _Tx:
        def __init__(self, con):
            self.con = con

        def __enter__(self):
            self.con.execute("begin immediate")
            return self.con

        def __exit__(self, kind, *_):
            self.con.execute("rollback" if kind else "commit")

    def _tx(self):
        return self._Tx(self._con())

    def _all(self, sql, params=()):
        return [dict(r) for r in self._con().execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        r = self._con().execute(sql, params).fetchone()
        return dict(r) if r else None

    # users and sessions ---------------------------------------------------------------------------
    def sync_users(self, spec: str):
        """Create the users named in RECON_USERS (name:hash,...) and update their password hashes.
        Each user gets a workspace of their own on first sight."""
        for pair in filter(None, (p.strip() for p in (spec or "").split(","))):
            name, _, pw_hash = pair.partition(":")
            if not name or not pw_hash.startswith("scrypt."):
                raise ValueError(f"RECON_USERS entry for {name or '?'} needs a scrypt hash (python -m api.workspace hash)")
            with self._tx() as c:
                u = c.execute("select id from users where username = ?", (name,)).fetchone()
                if u:
                    c.execute("update users set password_hash = ? where id = ?", (pw_hash, u["id"]))
                    continue
                ws = new_id("w")
                c.execute("insert into workspaces values (?, ?, ?)", (ws, f"{name}'s workspace", now()))
                c.execute("insert into users values (?, ?, ?, ?, ?)", (new_id("u"), name, pw_hash, ws, now()))
                c.execute("insert into lists values (?, ?, ?, ?)", (new_id("l"), ws, "My list", now()))

    def login(self, username, password):
        """A session token for good credentials, None otherwise (the same work either way)."""
        u = self._one("select * from users where username = ?", (username,))
        ok = check_password(password, u["password_hash"] if u else hash_password("timing-equaliser"))
        if not (u and ok):
            return None
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        with self._tx() as c:
            c.execute("delete from sessions where expires < ?", (now(),))
            c.execute("insert into sessions values (?, ?, ?, ?)", (self._token_hash(token), u["id"], now(), expires))
        return token

    @staticmethod
    def _token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()  # a leaked database holds no usable tokens

    def session_user(self, token):
        if not token:
            return None
        return self._one("""select u.id, u.username, u.workspace_id from sessions s join users u on u.id = s.user_id
                            where s.token_hash = ? and s.expires > ?""", (self._token_hash(token), now()))

    def logout(self, token):
        with self._tx() as c:
            c.execute("delete from sessions where token_hash = ?", (self._token_hash(token or ""),))

    def user_by_name(self, username):
        return self._one("select id, username, workspace_id from users where username = ?", (username,))

    # the whole workspace, for the app to start from -------------------------------------------------
    def snapshot(self, ws):
        entries = {}
        for r in self._all("""select i.account_id, i.list_id, min(i.added) over (partition by i.account_id) added, s.status
                              from list_items i join lists l on l.id = i.list_id
                              left join account_status s on s.workspace_id = l.workspace_id and s.account_id = i.account_id
                              where l.workspace_id = ? order by i.added""", (ws,)):
            e = entries.setdefault(r["account_id"], {"status": r["status"] or "to_contact", "added": r["added"], "lists": []})
            e["lists"].append(r["list_id"])
        return {"lists": self.lists(ws), "entries": entries, "searches": self.searches(ws), "profile": self.profile(ws)}

    # lists --------------------------------------------------------------------------------------
    def lists(self, ws):
        return self._all("""select l.id, l.name, l.created, count(i.account_id) n from lists l
                            left join list_items i on i.list_id = l.id where l.workspace_id = ?
                            group by l.id order by l.created, l.id""", (ws,))

    def find_list(self, ws, id_or_name):
        return self._one("select * from lists where workspace_id = ? and (id = ? or lower(name) = lower(?))",
                         (ws, id_or_name, id_or_name))

    def create_list(self, ws, name, list_id=None):
        list_id = list_id or new_id("l")
        if not ID.match(list_id):
            raise ValueError("bad list id")
        with self._tx() as c:
            if c.execute("select count(*) from lists where workspace_id = ?", (ws,)).fetchone()[0] >= MAX_LISTS:
                raise LimitError(f"a workspace holds at most {MAX_LISTS} lists")
            c.execute("insert into lists values (?, ?, ?, ?)", (list_id, ws, name.strip()[:60] or "Untitled list", now()))
        return self.find_list(ws, list_id)

    def rename_list(self, ws, list_id, name):
        with self._tx() as c:
            c.execute("update lists set name = ? where id = ? and workspace_id = ?", (name.strip()[:60], list_id, ws))

    def delete_list(self, ws, list_id):
        with self._tx() as c:
            c.execute("delete from lists where id = ? and workspace_id = ?", (list_id, ws))
            self._drop_orphan_status(c, ws)

    def list_ids(self, ws, list_id):
        return [r["account_id"] for r in self._all("""select i.account_id from list_items i join lists l on l.id = i.list_id
                                                     where l.id = ? and l.workspace_id = ? order by i.account_id""", (list_id, ws))]

    def listed_ids(self, ws):
        """Every account in any of the workspace's lists: what "not in my lists" leaves out."""
        return [r["account_id"] for r in self._all("""select distinct i.account_id from list_items i join lists l on l.id = i.list_id
                                                     where l.workspace_id = ? order by 1""", (ws,))]

    def add_items(self, ws, list_id, account_ids):
        with self._tx() as c:
            if not c.execute("select 1 from lists where id = ? and workspace_id = ?", (list_id, ws)).fetchone():
                raise KeyError(list_id)
            listed = {r[0] for r in c.execute("""select distinct i.account_id from list_items i join lists l on l.id = i.list_id
                                                 where l.workspace_id = ?""", (ws,))}
            fresh = [a for a in dict.fromkeys(account_ids) if a not in listed]
            if len(listed) + len(fresh) > MAX_LISTED:
                raise LimitError(f"a workspace holds at most {MAX_LISTED:,} listed accounts")
            t = now()
            before = c.execute("select count(*) from list_items where list_id = ?", (list_id,)).fetchone()[0]
            c.executemany("insert into list_items values (?, ?, ?) on conflict do nothing", [(list_id, a, t) for a in account_ids])
            c.executemany("insert into account_status values (?, ?, 'to_contact', ?) on conflict do nothing",
                          [(ws, a, t) for a in account_ids])
            after = c.execute("select count(*) from list_items where list_id = ?", (list_id,)).fetchone()[0]
        return {"added": after - before, "in_list": after}

    def remove_items(self, ws, list_id, account_ids):
        with self._tx() as c:
            c.executemany("""delete from list_items where list_id = ? and account_id = ?
                             and list_id in (select id from lists where workspace_id = ?)""",
                          [(list_id, a, ws) for a in account_ids])
            self._drop_orphan_status(c, ws)

    @staticmethod
    def _drop_orphan_status(c, ws):
        # an account in none of the workspace's lists has no status to keep
        c.execute("""delete from account_status where workspace_id = ? and account_id not in (
                       select i.account_id from list_items i join lists l on l.id = i.list_id where l.workspace_id = ?)""", (ws, ws))

    def set_status(self, ws, account_id, status):
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        with self._tx() as c:
            c.execute("update account_status set status = ?, updated = ? where workspace_id = ? and account_id = ?",
                      (status, now(), ws, account_id))

    # saved searches -----------------------------------------------------------------------------
    def searches(self, ws):
        rows = self._all("select * from saved_searches where workspace_id = ? order by created desc, id", (ws,))
        for r in rows:
            r["filters"], r["profile"] = json.loads(r["filters"]), json.loads(r["profile"])
            r.pop("workspace_id")
            r["lastRun"], r["lastRunAt"] = r.pop("last_run"), r.pop("last_run_at")
        return rows

    def find_search(self, ws, id_or_name):
        return next((s for s in self.searches(ws) if s["id"] == id_or_name or s["name"].lower() == id_or_name.lower()), None)

    def save_search(self, ws, name, filters, profile, build, search_id=None):
        search_id = search_id or new_id("s")
        if not ID.match(search_id):
            raise ValueError("bad search id")
        with self._tx() as c:
            if c.execute("select count(*) from saved_searches where workspace_id = ?", (ws,)).fetchone()[0] >= MAX_SEARCHES:
                raise LimitError(f"a workspace holds at most {MAX_SEARCHES} saved searches")
            c.execute("insert into saved_searches values (?, ?, ?, ?, ?, ?, ?, ?, 'daily')",
                      (search_id, ws, name.strip()[:60] or "Saved search", json.dumps(filters), json.dumps(profile),
                       now(), build, now()))
        return self.find_search(ws, search_id)

    def mark_run(self, ws, search_id, build):
        with self._tx() as c:
            c.execute("update saved_searches set last_run = ?, last_run_at = ? where id = ? and workspace_id = ?",
                      (build, now(), search_id, ws))

    def set_schedule(self, ws, search_id, schedule):
        if schedule not in ("daily", "manual"):
            raise ValueError("schedule is daily or manual")
        with self._tx() as c:
            c.execute("update saved_searches set schedule = ? where id = ? and workspace_id = ?", (schedule, search_id, ws))

    def delete_search(self, ws, search_id):
        with self._tx() as c:
            c.execute("delete from saved_searches where id = ? and workspace_id = ?", (search_id, ws))

    # profile ------------------------------------------------------------------------------------
    def profile(self, ws):
        r = self._one("select data from profiles where workspace_id = ?", (ws,))
        return json.loads(r["data"]) if r else None

    def save_profile(self, ws, data):
        with self._tx() as c:
            c.execute("""insert into profiles values (?, ?, ?)
                         on conflict (workspace_id) do update set data = excluded.data, updated = excluded.updated""",
                      (ws, json.dumps(data), now()))


_ws = None
_lock = threading.Lock()


def get_workspace():
    global _ws
    if _ws is None:
        with _lock:
            if _ws is None:
                w = Workspace(DB)
                w.sync_users(os.environ.get("RECON_USERS", ""))
                _ws = w
    return _ws


if __name__ == "__main__":
    # python -m api.workspace hash   -> prints a scrypt hash for RECON_USERS (the password isn't echoed)
    if sys.argv[1:] == ["hash"]:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Again: "):
            sys.exit("passwords differ")
        print(hash_password(pw))
    else:
        sys.exit("usage: python -m api.workspace hash")
