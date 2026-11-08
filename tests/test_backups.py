from __future__ import annotations

from serverpilot.extensions import db
from serverpilot.models import (
    AgentTask,
    Backup,
    BackupStatus,
    TaskStatus,
    TaskType,
)
from serverpilot.services.backups import (
    apply_backup_task_result,
    create_website_backup,
    request_restore,
)
from serverpilot.services.deployments import apply_task_result
from tests.factories import make_user, make_website
from tests.test_agent import _register


def test_backup_request_and_result_lifecycle(client, app):
    _register(client, uid="backup-agent", hostname="backup.example.com")
    with app.app_context():
        user = make_user("backup@example.com")
        website = make_website(user)
        db.session.commit()

        backup = create_website_backup(user, website)
        task = AgentTask.query.filter_by(
            website_id=website.id, task_type=TaskType.BACKUP
        ).one()
        assert backup.status == BackupStatus.PENDING
        assert task.status == TaskStatus.PENDING

        task.status = TaskStatus.CLAIMED
        db.session.commit()
        assert apply_task_result(
            task,
            succeeded=True,
            result={
                "backup_path": "/var/lib/serverpilot/backups/archive.tar.gz",
                "size_bytes": 4096,
                "checksum_sha256": "a" * 64,
            },
            error=None,
        )

        restored = db.session.get(Backup, backup.id)
        assert restored.status == BackupStatus.COMPLETED
        assert restored.size_bytes == 4096
        assert restored.storage_path.endswith("archive.tar.gz")


def test_restore_requires_stopped_website_and_completed_backup(client, app):
    _register(client, uid="restore-agent", hostname="restore.example.com")
    with app.app_context():
        user = make_user("restore@example.com")
        website = make_website(user)
        backup = create_website_backup(user, website)
        backup.status = BackupStatus.COMPLETED
        backup.storage_path = "/var/lib/serverpilot/backups/archive.tar.gz"
        AgentTask.query.filter_by(
            website_id=website.id, task_type=TaskType.BACKUP
        ).update({"status": TaskStatus.CANCELLED}, synchronize_session=False)
        db.session.commit()

        task = request_restore(user, website, backup)
        assert task.task_type == TaskType.RESTORE
        backup = db.session.get(Backup, backup.id)
        assert backup.status == BackupStatus.RESTORING

        apply_backup_task_result(
            task,
            succeeded=True,
            result={"restored": True},
            error=None,
        )
        db.session.commit()
        assert backup.status == BackupStatus.RESTORED
        assert backup.restore_count == 1
