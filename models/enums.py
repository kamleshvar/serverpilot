"""Domain enums stored as portable, validated VARCHAR + CHECK constraints."""

from __future__ import annotations

from enum import Enum


class UserStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"


class IdentityProvider(str, Enum):
    GOOGLE = "google"
    GITHUB = "github"


class DomainStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"


class ServerStatus(str, Enum):
    PROVISIONING = "provisioning"
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    DISABLED = "disabled"


class ServerApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ServerConnectionStatus(str, Enum):
    UNKNOWN = "unknown"
    CONNECTED = "connected"
    FAILED = "failed"
    OFFLINE = "offline"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AgentInstallStatus(str, Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED = "installed"
    FAILED = "failed"


class AgentStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    OFFLINE = "offline"
    REVOKED = "revoked"


class WebsiteStatus(str, Enum):
    PENDING = "pending"
    BUILDING = "building"
    RUNNING = "running"
    USER_STOPPED = "user_stopped"
    ADMIN_FORCED_STOP = "admin_forced_stop"
    QUOTA_STOPPED = "quota_stopped"
    FAILED = "failed"
    DELETING = "deleting"
    DELETED = "deleted"


class Framework(str, Enum):
    FLASK = "flask"
    PYTHON = "python"
    NODE = "node"
    STATIC = "static"
    OTHER = "other"


class StopReason(str, Enum):
    USER_REQUESTED = "user_requested"
    ADMIN_FORCED_STOP = "admin_forced_stop"
    RAM_QUOTA_EXCEEDED = "ram_quota_exceeded"
    STORAGE_QUOTA_EXCEEDED = "storage_quota_exceeded"
    USER_SUSPENDED = "user_suspended"
    DEPLOYMENT_REPLACED = "deployment_replaced"
    HEALTHCHECK_FAILED = "healthcheck_failed"
    SERVER_DRAINING = "server_draining"
    MAINTENANCE = "maintenance"


class DeploymentStatus(str, Enum):
    QUEUED = "queued"
    BUILDING = "building"
    DEPLOYING = "deploying"
    HEALTH_CHECK = "health_check"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class DeploymentTrigger(str, Enum):
    MANUAL = "manual"
    REDEPLOY = "redeploy"
    GITHUB_PUSH = "github_push"
    ROLLBACK = "rollback"
    ADMIN = "admin"


class InitiatorType(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogSource(str, Enum):
    BUILD = "build"
    DEPLOYMENT = "deployment"
    APPLICATION = "application"
    CONTAINER = "container"
    SYSTEM = "system"


class ContainerStatus(str, Enum):
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    EXITED = "exited"
    FAILED = "failed"
    REMOVED = "removed"


class ResourceScope(str, Enum):
    GLOBAL = "global"
    SERVER = "server"
    USER = "user"
    WEBSITE = "website"


class DnsRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"
    MX = "MX"
    NS = "NS"


class DnsStatus(str, Enum):
    UNKNOWN = "unknown"
    PENDING = "pending"
    VALID = "valid"
    MISSING = "missing"
    CONFLICT = "conflict"
    ERROR = "error"


class GithubInstallationStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class BackupScope(str, Enum):
    WEBSITE = "website"
    DATABASE = "database"
    CONFIG = "config"


class BackupStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RESTORING = "restoring"
    RESTORED = "restored"
    EXPIRED = "expired"


class NotificationAudience(str, Enum):
    USER = "user"
    ADMIN = "admin"


class Severity(str, Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AdminActionResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class TaskType(str, Enum):
    DEPLOY = "deploy"
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    DELETE = "delete"
    COLLECT_LOGS = "collect_logs"
    COLLECT_METRICS = "collect_metrics"
    BACKUP = "backup"
    RESTORE = "restore"
    SYNC_PROXY = "sync_proxy"
    REMOVE = "remove"


class TaskStatus(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class AgentTaskPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
