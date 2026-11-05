"""
Webhook Integration Module

Provides Discord and Slack webhook integration for real-time notifications
of security findings during web application reconnaissance scans.

Supports:
- Discord embeds with severity-based color coding
- Slack-formatted text messages
- Proxy configuration and authentication
- Configurable notification thresholds
"""

import logging
import requests
from typing import Optional
from web_app.core.findings import Severity

logger = logging.getLogger(__name__)


def webhook_notify(f, cfg):
    """POST a finding to a Discord/Slack incoming webhook URL.

    Args:
        f: Finding object with title, severity, description, phase, timestamp
        cfg: ScanConfig object with webhook_url and proxy settings

    Formats the finding into either Discord embed or Slack message format
    based on the webhook URL domain, then POSTs to the webhook endpoint.
    Handles timeouts and network errors gracefully with logging.
    """
    color_map = {Severity.INFO: 0x3498db, Severity.LOW: 0x2ecc71,
                 Severity.MEDIUM: 0xf1c40f, Severity.HIGH: 0xe67e22,
                 Severity.CRITICAL: 0xe74c3c}
    url = cfg.webhook_url
    if not url:
        return

    try:
        # Discord-style embed
        if "discord" in url.lower():
            payload = {
                "embeds": [{
                    "title":       f"[{f.severity.value}] {f.title}",
                    "description": f.description[:1500],
                    "color":       color_map.get(f.severity, 0x95a5a6),
                    "fields": [
                        {"name": "Target", "value": cfg.target, "inline": True},
                        {"name": "Phase",  "value": f.phase or "n/a", "inline": True},
                    ],
                    "timestamp": f.timestamp,
                }]
            }
        else:
            # Slack-style
            payload = {
                "text": f"*[{f.severity.value}]* {f.title}\n"
                        f"_Target:_ `{cfg.target}` | _Phase:_ `{f.phase}`\n"
                        f"{f.description[:1500]}"
            }

        proxies = {"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None
        resp = requests.post(url, json=payload, timeout=5, verify=False, proxies=proxies)

        if resp.status_code >= 400:
            if logger:
                logger.warning(f"Webhook notification failed: HTTP {resp.status_code}")
        elif logger:
            logger.debug(f"Webhook notification sent for {f.severity.value}: {f.title}")

    except requests.exceptions.Timeout:
        if logger:
            logger.warning("Webhook notification timed out")
    except requests.exceptions.RequestException as e:
        if logger:
            logger.warning(f"Webhook notification failed: {type(e).__name__}: {e}")
    except Exception as e:
        if logger:
            logger.error(f"Unexpected error in webhook notification: {e}")
