"""
WebRecon Integrations

External service integrations:
- webhook: Discord/Slack notifications
- pentestdb: PentestDB backend storage
"""

from .pentestdb import pentestdb_push

__all__ = ["pentestdb_push"]
