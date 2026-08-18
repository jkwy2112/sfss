import json
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .auth import valid_username


class LdapSyncError(Exception):
    pass


CONFIG_DEFAULTS = {
    "enabled": False,
    "uri": "",
    "base_dn": "",
    "bind_dn": "",
    "user_filter": "(objectClass=person)",
    "username_attribute": "uid",
    "approver_group_dn": "",
    "deprovision_missing": False,
}
_KEY_PREFIX = "ldap_sync_"
_DN_PATTERN = re.compile(r"^[\x20-\x7e]{1,256}$")
_ATTRIBUTE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _load_raw(store) -> Dict:
    doc = dict(CONFIG_DEFAULTS)
    for name, default in CONFIG_DEFAULTS.items():
        stored = store.get_config(_KEY_PREFIX + name, None)
        if stored is None:
            continue
        if isinstance(default, bool):
            doc[name] = stored == "true"
        else:
            doc[name] = stored
    return doc


def ldap_sync_document(store, settings) -> Dict:
    config = _load_raw(store)
    state = store.one(
        "SELECT last_run_at,last_status,last_summary,bind_secret FROM ldap_sync_state WHERE id=1") or {}
    document = dict(config)
    document["bind_password_set"] = bool(state.get("bind_secret"))
    document["production_staged"] = settings.environment == "production"
    document["last_run"] = None
    if state.get("last_run_at"):
        try: summary = json.loads(state.get("last_summary") or "{}")
        except json.JSONDecodeError: summary = {}
        document["last_run"] = {"at": state["last_run_at"], "status": state.get("last_status", ""),
                                "summary": summary}
    return document


def _validate_uri(uri: str, production: bool):
    try:
        parsed = urlparse(uri); _ = parsed.port
        if (parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname or
                parsed.username or parsed.password or parsed.path not in {"", "/"} or
                parsed.query or parsed.fragment):
            raise ValueError
    except ValueError as exc:
        raise LdapSyncError("LDAP URI 必须是 ldap:// 或 ldaps:// 的主机端点") from exc
    if production and parsed.scheme != "ldaps":
        raise LdapSyncError("生产环境 LDAP 同步必须使用 ldaps://")


def _validate_dn(value: str, label: str, required: bool):
    if not value:
        if required: raise LdapSyncError(f"{label} 不能为空")
        return
    if not _DN_PATTERN.fullmatch(value):
        raise LdapSyncError(f"{label} 包含非法字符或超长")


def save_ldap_sync_config(store, settings, data: Dict, actor: str, audit=None) -> Dict:
    current = _load_raw(store)
    doc = {name: current[name] for name in CONFIG_DEFAULTS}
    if not isinstance(data, dict):
        raise LdapSyncError("请求体必须是 JSON 对象")
    for name in ("enabled", "deprovision_missing"):
        if name in data and not isinstance(data[name], bool):
            raise LdapSyncError(f"{name} 必须是布尔值")
        if name in data: doc[name] = data[name]
    for name in ("uri", "base_dn", "bind_dn", "user_filter", "username_attribute", "approver_group_dn"):
        if name in data:
            if not isinstance(data[name], str):
                raise LdapSyncError(f"{name} 必须是字符串")
            doc[name] = data[name].strip()
    password = data.get("bind_password")
    if password is not None and not isinstance(password, str):
        raise LdapSyncError("bind_password 必须是字符串")
    if password: 
        if len(password) > 256 or any(ord(ch) < 32 for ch in password):
            raise LdapSyncError("bind_password 包含非法字符或超长")
    if not doc["user_filter"]: doc["user_filter"] = CONFIG_DEFAULTS["user_filter"]
    if not doc["username_attribute"]: doc["username_attribute"] = CONFIG_DEFAULTS["username_attribute"]
    if doc["enabled"]:
        if not doc["uri"]: raise LdapSyncError("启用同步时必须配置 LDAP URI")
        _validate_uri(doc["uri"], settings.environment == "production")
        _validate_dn(doc["base_dn"], "Base DN", True)
        _validate_dn(doc["bind_dn"], "Bind DN", True)
    else:
        if doc["uri"]: _validate_uri(doc["uri"], settings.environment == "production")
        _validate_dn(doc["base_dn"], "Base DN", False)
        _validate_dn(doc["bind_dn"], "Bind DN", False)
    _validate_dn(doc["approver_group_dn"], "审批员组 DN", False)
    filter_value = doc["user_filter"]
    if not (filter_value.startswith("(") and filter_value.endswith(")") and
            _DN_PATTERN.fullmatch(filter_value)):
        raise LdapSyncError("用户过滤器必须是形如 (objectClass=person) 的括号表达式")
    if not _ATTRIBUTE_PATTERN.fullmatch(doc["username_attribute"]):
        raise LdapSyncError("用户名属性只能包含字母、数字、下划线和连字符")
    state = store.one("SELECT bind_secret FROM ldap_sync_state WHERE id=1") or {}
    if doc["enabled"] and not (state.get("bind_secret") or password):
        raise LdapSyncError("启用同步前必须先配置 Bind 密码")
    now = int(time.time())
    statements = []
    for name, value in doc.items():
        if isinstance(value, bool): stored = "true" if value else "false"
        else: stored = value
        statements.append((
            "INSERT INTO system_config(key,value,updated_at,updated_by) VALUES(?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            (_KEY_PREFIX + name, stored, now, actor)))
    if password:
        statements.append((
            "INSERT INTO ldap_sync_state(id,bind_secret) VALUES(1,?) "
            "ON CONFLICT(id) DO UPDATE SET bind_secret=excluded.bind_secret", (password,)))
    audited = dict(audit) if audit is not None else {
        "request_id": f"ldap-sync-config-{now}", "actor": actor,
        "action": "admin.ldap_sync.config", "object_id": None, "outcome": "success",
        "source_zone": "admin", "remote_addr": "local", "details": {}}
    details = dict(audited.get("details") or {})
    details.update({"enabled": doc["enabled"], "uri": doc["uri"], "base_dn": doc["base_dn"],
                    "approver_group_dn": doc["approver_group_dn"],
                    "deprovision_missing": doc["deprovision_missing"],
                    "bind_password_changed": bool(password)})
    audited["details"] = details
    store.transaction_audited(tuple(statements), audit=audited)
    return ldap_sync_document(store, settings)


class Ldap3Directory:
    def __init__(self, uri: str, bind_dn: str, password: str, ca_file: str = ""):
        try:
            import ldap3
        except ImportError as exc:
            raise LdapSyncError("ldap3 库未安装：请安装 sfss[ldap] 依赖后再执行同步") from exc
        import ssl
        use_ssl = uri.lower().startswith("ldaps")
        tls = None
        if use_ssl:
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file or None)
        try:
            server = ldap3.Server(uri, use_ssl=use_ssl, tls=tls, connect_timeout=10)
            self.connection = ldap3.Connection(server, user=bind_dn, password=password,
                                               auto_bind=True, receive_timeout=30)
        except Exception as exc:
            raise LdapSyncError(f"无法连接或绑定 LDAP 目录: {type(exc).__name__}") from exc

    def search_users(self, base_dn: str, user_filter: str, username_attribute: str):
        try:
            entries = self.connection.extend.standard.paged_search(
                base_dn, user_filter, attributes=[username_attribute],
                paged_size=500, generator=True)
            users: List[Tuple[str, str]] = []
            for entry in entries:
                if entry.get("type") != "searchResEntry": continue
                value = (entry.get("attributes") or {}).get(username_attribute)
                values = value if isinstance(value, list) else [value]
                for username in values:
                    if isinstance(username, str) and username:
                        users.append((entry.get("dn", ""), username))
            return users
        except Exception as exc:
            raise LdapSyncError(f"LDAP 用户检索失败: {type(exc).__name__}") from exc

    def search_group_members(self, group_dn: str):
        try:
            self.connection.search(group_dn, "(objectClass=*)",
                                   attributes=["member", "memberUid"], search_scope="BASE")
            members: Set[str] = set()
            member_uids: Set[str] = set()
            for entry in self.connection.response:
                if entry.get("type") != "searchResEntry": continue
                attributes = entry.get("attributes") or {}
                for value in attributes.get("member") or []:
                    if isinstance(value, str) and value: members.add(value)
                for value in attributes.get("memberUid") or []:
                    if isinstance(value, str) and value: member_uids.add(value)
            return members, member_uids
        except Exception as exc:
            raise LdapSyncError(f"LDAP 组成员检索失败: {type(exc).__name__}") from exc

    def close(self):
        try: self.connection.unbind()
        except Exception: pass


def _chunked(names, size=400):
    for index in range(0, len(names), size):
        yield names[index:index + size]


def _record_run(store, actor: str, status: str, summary: Dict):
    now = int(time.time())
    store.transaction_audited((
        ("INSERT INTO ldap_sync_state(id,last_run_at,last_status,last_summary) VALUES(1,?,?,?) "
         "ON CONFLICT(id) DO UPDATE SET last_run_at=excluded.last_run_at,"
         "last_status=excluded.last_status,last_summary=excluded.last_summary",
         (now, status, json.dumps(summary, ensure_ascii=False, sort_keys=True))),
    ), audit={"request_id": f"ldap-sync-run-{now}", "actor": actor,
              "action": "admin.ldap_sync.run", "object_id": None, "outcome": status,
              "source_zone": "admin", "remote_addr": "local", "details": summary})


def run_ldap_sync(store, settings, directory=None, actor: str = "system") -> Dict:
    config = _load_raw(store)
    if not config["enabled"]:
        raise LdapSyncError("LDAP 同步未启用")
    state = store.one("SELECT bind_secret FROM ldap_sync_state WHERE id=1") or {}
    password = state.get("bind_secret") or ""
    if directory is None and not password:
        raise LdapSyncError("未配置 Bind 密码，无法连接目录")
    started_ms = int(time.time() * 1000)
    owns_directory = directory is None
    try:
        if directory is None:
            try:
                directory = Ldap3Directory(config["uri"], config["bind_dn"], password,
                                           ca_file=getattr(settings, "ldap_ca_file", "") or "")
            except LdapSyncError as exc:
                _record_run(store, actor, "error", {"error": str(exc)})
                raise
        try:
            entries = directory.search_users(config["base_dn"], config["user_filter"],
                                             config["username_attribute"])
            members = (directory.search_group_members(config["approver_group_dn"])
                       if config["approver_group_dn"] else (set(), set()))
        except LdapSyncError as exc:
            _record_run(store, actor, "error", {"error": str(exc)})
            raise
        seen: Set[str] = set()
        dn_map: Dict[str, str] = {}
        skipped_invalid = 0
        for dn, username in entries:
            if not valid_username(username):
                skipped_invalid += 1; continue
            if username in seen: continue
            seen.add(username)
            dn_map[dn.lower()] = username
        if not seen:
            error = LdapSyncError("目录检索返回 0 个有效用户，已中止以防误停用")
            _record_run(store, actor, "error", {"error": str(error)})
            raise error
        member_dns, member_uids = members
        approver_names = {dn_map[dn.lower()] for dn in member_dns if dn.lower() in dn_map}
        approver_names |= (seen & member_uids)
        statements = []
        for username in sorted(seen):
            statements.append((
                "INSERT INTO users(username,global_admin,approver,principal_type,enabled,ldap_synced) "
                "VALUES(?,0,0,'human',1,1) ON CONFLICT(username) DO UPDATE SET ldap_synced=1, "
                "enabled=CASE WHEN users.global_admin=0 AND users.principal_type='human' "
                "THEN 1 ELSE users.enabled END",
                (username,)))
        approver_list = sorted(approver_names)
        for batch in _chunked(approver_list):
            placeholders = ",".join("?" for _ in batch)
            statements.append((
                f"UPDATE users SET approver=1 WHERE principal_type='human' AND username IN ({placeholders})",
                tuple(batch)))
        to_disable: List[str] = []
        if config["deprovision_missing"]:
            placeholders = ",".join("?" for _ in seen)
            previously_synced = [row["username"] for row in store.all(
                "SELECT username FROM users WHERE ldap_synced=1 AND enabled=1 AND global_admin=0 "
                f"AND principal_type='human' AND username NOT IN ({placeholders})",
                tuple(sorted(seen)))]
            to_disable = previously_synced
            for batch in _chunked(to_disable):
                placeholders = ",".join("?" for _ in batch)
                statements.append((
                    f"UPDATE users SET enabled=0 WHERE username IN ({placeholders}) "
                    "AND global_admin=0 AND principal_type='human' AND ldap_synced=1",
                    tuple(batch)))
        summary = {"status": "ok", "users_seen": len(entries), "users_synced": len(seen),
                   "skipped_invalid": skipped_invalid, "approvers_granted": len(approver_list),
                   "disabled": len(to_disable), "disabled_sample": sorted(to_disable)[:20],
                   "duration_ms": int(time.time() * 1000) - started_ms}
        now = int(time.time())
        statements.append((
            "INSERT INTO ldap_sync_state(id,last_run_at,last_status,last_summary) VALUES(1,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET last_run_at=excluded.last_run_at,"
            "last_status=excluded.last_status,last_summary=excluded.last_summary",
            (now, "ok", json.dumps(summary, ensure_ascii=False, sort_keys=True))))
        store.transaction_audited(tuple(statements), audit={
            "request_id": f"ldap-sync-run-{now}", "actor": actor,
            "action": "admin.ldap_sync.run", "object_id": None, "outcome": "success",
            "source_zone": "admin", "remote_addr": "local", "details": summary})
        return summary
    finally:
        if owns_directory and directory is not None:
            directory.close()
