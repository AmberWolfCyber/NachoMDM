from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import sqlite3
import time


def now() -> int:
    return int(time.time())


@dataclass(slots=True)
class Enrollment:
    id: int
    email: str
    device_id: str
    provider_id: str
    cert_thumbprint: str
    cert_subject: str
    client_cert_pem: str
    auth_policy: str
    agent_state: str


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists enrollments (
                    id integer primary key autoincrement,
                    email text not null,
                    device_id text not null,
                    provider_id text not null,
                    cert_thumbprint text not null unique,
                    cert_subject text not null,
                    client_cert_pem text not null,
                    auth_policy text not null,
                    additional_context_json text not null default '{}',
                    agent_state text not null default 'pending',
                    created_at integer not null,
                    last_seen_at integer
                );

                create table if not exists sync_sessions (
                    id integer primary key autoincrement,
                    enrollment_id integer,
                    cert_thumbprint text,
                    session_id text,
                    msg_id text,
                    source text,
                    target text,
                    mode text,
                    request_xml text not null,
                    response_xml text,
                    created_at integer not null
                );

                create table if not exists events (
                    id integer primary key autoincrement,
                    enrollment_id integer,
                    event_type text not null,
                    payload_json text not null,
                    created_at integer not null
                );
                """
            )

    def record_enrollment(
        self,
        *,
        email: str,
        device_id: str,
        provider_id: str,
        cert_thumbprint: str,
        cert_subject: str,
        client_cert_pem: str,
        auth_policy: str,
        additional_context: dict[str, str],
    ) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "select id from enrollments where cert_thumbprint = ?",
                (cert_thumbprint,),
            ).fetchone()
            if row:
                enrollment_id = int(row["id"])
                conn.execute(
                    """
                    update enrollments
                       set email = ?, device_id = ?, provider_id = ?,
                           cert_subject = ?, client_cert_pem = ?, auth_policy = ?,
                           additional_context_json = ?, last_seen_at = ?
                     where id = ?
                    """,
                    (
                        email,
                        device_id,
                        provider_id,
                        cert_subject,
                        client_cert_pem,
                        auth_policy,
                        json.dumps(additional_context, sort_keys=True),
                        now(),
                        enrollment_id,
                    ),
                )
                return enrollment_id

            cur = conn.execute(
                """
                insert into enrollments (
                    email, device_id, provider_id, cert_thumbprint, cert_subject,
                    client_cert_pem, auth_policy, additional_context_json,
                    created_at, last_seen_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    device_id,
                    provider_id,
                    cert_thumbprint,
                    cert_subject,
                    client_cert_pem,
                    auth_policy,
                    json.dumps(additional_context, sort_keys=True),
                    now(),
                    now(),
                ),
            )
            return int(cur.lastrowid)

    def get_enrollment_by_thumbprint(self, thumbprint: str) -> Enrollment | None:
        with self.connect() as conn:
            row = conn.execute(
                "select * from enrollments where cert_thumbprint = ?",
                (thumbprint,),
            ).fetchone()
        return _row_to_enrollment(row) if row else None

    def get_latest_enrollment_by_device_id(self, device_id: str) -> Enrollment | None:
        with self.connect() as conn:
            row = conn.execute(
                "select * from enrollments where device_id = ? order by id desc limit 1",
                (device_id,),
            ).fetchone()
        return _row_to_enrollment(row) if row else None

    def touch_enrollment(self, enrollment_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "update enrollments set last_seen_at = ? where id = ?",
                (now(), enrollment_id),
            )

    def mark_agent_state(self, enrollment_id: int, state: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "update enrollments set agent_state = ? where id = ?",
                (state, enrollment_id),
            )

    def record_sync_session(
        self,
        *,
        enrollment_id: int | None,
        cert_thumbprint: str | None,
        session_id: str,
        msg_id: str,
        source: str,
        target: str,
        mode: str,
        request_xml: str,
        response_xml: str,
    ) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """
                insert into sync_sessions (
                    enrollment_id, cert_thumbprint, session_id, msg_id, source,
                    target, mode, request_xml, response_xml, created_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    enrollment_id,
                    cert_thumbprint,
                    session_id,
                    msg_id,
                    source,
                    target,
                    mode,
                    request_xml,
                    response_xml,
                    now(),
                ),
            )
            return int(cur.lastrowid)

    def record_event(self, enrollment_id: int | None, event_type: str, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert into events (enrollment_id, event_type, payload_json, created_at) values (?, ?, ?, ?)",
                (enrollment_id, event_type, json.dumps(payload, sort_keys=True), now()),
            )


def _row_to_enrollment(row: sqlite3.Row) -> Enrollment:
    return Enrollment(
        id=int(row["id"]),
        email=str(row["email"]),
        device_id=str(row["device_id"]),
        provider_id=str(row["provider_id"]),
        cert_thumbprint=str(row["cert_thumbprint"]),
        cert_subject=str(row["cert_subject"]),
        client_cert_pem=str(row["client_cert_pem"]),
        auth_policy=str(row["auth_policy"]),
        agent_state=str(row["agent_state"]),
    )
