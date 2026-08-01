"""Scoped reset helpers for the local Chio knowledge base."""

from __future__ import annotations

import argparse
import asyncio
import os
import pathlib
import shutil
from typing import Any

import asyncpg
from neo4j import AsyncGraphDatabase

POSTGRES_URL = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL") or (
    "postgres://cocoindex:cocoindex@localhost:55432/chio_kb"
)
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "demodemo")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")
COCOINDEX_DB = os.environ.get("COCOINDEX_DB", "")


async def reset_postgres() -> dict[str, Any]:
    conn = await asyncpg.connect(POSTGRES_URL)
    try:
        rows = await conn.fetch(
            """
            SELECT schemaname, tablename
            FROM pg_tables
            WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
              AND (
                schemaname IN ('chio_kb', 'cocoindex')
                OR tablename LIKE 'cocoindex%'
                OR tablename LIKE '_cocoindex%'
                OR tablename LIKE 'chio_kb%'
              )
            ORDER BY schemaname, tablename
            """
        )
        dropped: list[str] = []
        for row in rows:
            qualified = f'"{row["schemaname"]}"."{row["tablename"]}"'
            await conn.execute(f"DROP TABLE IF EXISTS {qualified} CASCADE")
            dropped.append(f'{row["schemaname"]}.{row["tablename"]}')
        await conn.execute('CREATE SCHEMA IF NOT EXISTS "chio_kb"')
        return {"dropped_tables": dropped}
    finally:
        await conn.close()


async def reset_neo4j() -> dict[str, Any]:
    driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        async with driver.session(database=NEO4J_DATABASE) as session:
            result = await session.run(
                """
                MATCH (n)
                WHERE any(label IN labels(n) WHERE label STARTS WITH 'Chio')
                WITH collect(n) AS nodes
                FOREACH (node IN nodes | DETACH DELETE node)
                RETURN size(nodes) AS deleted_nodes
                """
            )
            record = await result.single()
            return {"deleted_nodes": int(record["deleted_nodes"] if record else 0)}
    finally:
        await driver.close()


async def reset_all() -> dict[str, Any]:
    postgres, neo4j = await asyncio.gather(reset_postgres(), reset_neo4j())
    cocoindex_state = reset_cocoindex_state()
    return {"postgres": postgres, "neo4j": neo4j, "cocoindex_state": cocoindex_state}


def reset_cocoindex_state() -> dict[str, Any]:
    if not COCOINDEX_DB:
        return {"deleted": False, "reason": "COCOINDEX_DB is not set"}
    path = pathlib.Path(COCOINDEX_DB)
    if not path.is_absolute() or path == pathlib.Path("/") or "/cocoindex" not in path.as_posix():
        return {"deleted": False, "reason": f"refusing unsafe path {path}"}
    if not path.exists():
        return {"deleted": False, "path": str(path)}
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    return {"deleted": True, "path": str(path)}


async def _main_async(_: argparse.Namespace) -> int:
    result = await reset_all()
    print(result)
    return 0


def reset_main() -> None:
    parser = argparse.ArgumentParser(description="Clear KB-owned Postgres tables and Chio Neo4j nodes.")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main_async(args)))


if __name__ == "__main__":
    reset_main()
