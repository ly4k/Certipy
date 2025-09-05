from typing import Tuple

from neo4j import GraphDatabase


class BloodHoundError(Exception):
    pass


def resolve_type(labels: frozenset[str]):
    for type in ["User", "Group", "Computer"]:
        if type in labels:
            return type.upper()
    return "UNKNOWN"


class BloodHound:
    def __init__(
        self, user: str, password: str, host: str = "localhost", port: int = 7687
    ):
        self.driver = GraphDatabase.driver(
            f"neo4j://{host}:{port}",
            auth=(user, password),
        )

    def get_owned_sids(self):
        records, _, _ = self.driver.execute_query(
            "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE COALESCE(u.system_tags, '') CONTAINS 'owned' return g.objectid"
        )
        for record in records:
            yield record["g.objectid"]

    def lookup_sid(self, sid: str) -> Tuple[str, str]:
        records, _, _ = self.driver.execute_query(
            "MATCH (g {objectid:$sid}) return g", sid=sid
        )
        if records:
            return records[0]["g"]["name"], resolve_type(records[0]["g"].labels)
        raise BloodHoundError("SID not found")
