"""The unified identity model shared by every subcommand.

One Identity per non-human identity, whatever the platform: an Entra app registration, enterprise application,
managed identity or agent identity; an AWS IAM role or user; a GitHub App installation or deploy key; or an agent or
MCP connector known only from the register. Each carries its owners, credentials, grants and last activity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields

PLATFORMS = ("entra", "aws", "github", "register")


@dataclass
class Credential:
    kind: str  # client-secret, certificate, federated, sp-secret, sp-certificate, access-key, deploy-key, api-key
    key_id: str  # masked: last four characters only
    created: str | None = None
    expires: str | None = None
    last_used: str | None = None
    status: str = "Active"
    age_days: int | None = None
    expired: bool = False

    def ref(self) -> str:
        return f"{self.kind} {self.key_id}"


@dataclass
class Grant:
    kind: str  # application-permission, delegated-permission, directory-role, managed-policy, inline-policy, ...
    name: str
    scope: str = ""  # what it reaches: tenant, all users, one user, account, all repositories, a repository
    ref: str = ""  # the platform id or ARN needed to remove it
    score: int = 0  # blast-radius score, 0 to 100 (see docs/scoring.md)
    reason: str = ""  # why it scored what it did
    detail: dict = field(default_factory=dict)

    def key(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass
class Identity:
    id: str
    name: str
    platform: str
    type: str
    owners: list[str] = field(default_factory=list)
    enabled: bool = True
    created: str | None = None
    last_used: str | None = None
    activity_recorded: bool = False
    credentials: list[Credential] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    trust: list[str] = field(default_factory=list)
    agent: bool = False
    agent_signals: list[str] = field(default_factory=list)
    used_by: list[str] = field(default_factory=list)
    purpose: str = ""
    refs: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    blast_radius: int = 0
    days_since_use: int | None = None

    def add_owner(self, owner: str) -> None:
        owner = (owner or "").strip()
        if owner and owner not in self.owners:
            self.owners.append(owner)

    def add_source(self, name: str) -> None:
        if name and name not in self.sources:
            self.sources.append(name)

    def mark_agent(self, signal: str) -> None:
        self.agent = True
        if signal not in self.agent_signals:
            self.agent_signals.append(signal)

    def oldest_credential_days(self) -> int | None:
        ages = [c.age_days for c in self.credentials if c.age_days is not None]
        return max(ages) if ages else None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Identity:
        names = {f.name for f in fields(cls)}
        kw = {k: v for k, v in data.items() if k in names}
        cred_names = {f.name for f in fields(Credential)}
        grant_names = {f.name for f in fields(Grant)}
        kw["credentials"] = [
            Credential(**{k: v for k, v in c.items() if k in cred_names})
            for c in data.get("credentials") or []
            if isinstance(c, dict)
        ]
        kw["grants"] = [
            Grant(**{k: v for k, v in g.items() if k in grant_names})
            for g in data.get("grants") or []
            if isinstance(g, dict)
        ]
        for required in ("id", "name", "platform", "type"):
            kw.setdefault(required, "")
        return cls(**kw)
