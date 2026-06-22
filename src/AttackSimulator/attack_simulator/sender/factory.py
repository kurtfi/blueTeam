"""
Factory to instantiate and retrieve pluggable AlertSender implementations.
"""

from attack_simulator.sender.base import AlertSender
from attack_simulator.sender.file import FileAlertSender
from attack_simulator.sender.syslog import SyslogAlertSender
from attack_simulator.sender.webhook import WebhookAlertSender


def get_sender(sender_type: str, **kwargs) -> AlertSender:
    """
    Returns an instance of an AlertSender based on the sender_type.
    """
    st = sender_type.lower().strip()
    if st == "syslog":
        return SyslogAlertSender(
            host=kwargs.get("syslog_host"),
            port=kwargs.get("syslog_port"),
            protocol=kwargs.get("syslog_protocol"),
            rfc5424=kwargs.get("syslog_rfc5424", True),
        )
    elif st == "file":
        return FileAlertSender(file_path=kwargs.get("file_path"))
    elif st == "webhook":
        return WebhookAlertSender()
    else:
        # Default fallback
        return WebhookAlertSender()
