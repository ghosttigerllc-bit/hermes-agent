"""
Telegram MTProto platform adapter.

Uses Telethon for user-account Telegram messaging (not Bot API).
Key differences from the Bot API adapter:
- Full user capabilities (DM anyone first, larger files, no privacy mode)
- Phone number authentication (not bot token)
- Session persistence via Telethon's SQLite session
- Can operate as a real Telegram user

Requirements:
    pip install telethon
"""

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import (
        User,
        Chat,
        Channel,
        MessageEntityMention,
        MessageEntityMentionName,
        PeerUser,
        PeerChat,
        PeerChannel,
    )
    from telethon.tl.functions.messages import SetTypingRequest
    from telethon.tl.types import SendMessageTypingAction
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    TelegramClient = Any
    events = None

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    ProcessingOutcome,
    SendResult,
    cache_image_from_bytes,
    cache_audio_from_bytes,
    cache_document_from_bytes,
)

# Telegram message length limit (same for MTProto)
MAX_MESSAGE_LENGTH = 4096

GroupPolicy = str  # 'mention' | 'reply' | 'both' | 'off'


def check_telegram_mtproto_requirements() -> bool:
    """Check if Telethon is installed."""
    if not TELETHON_AVAILABLE:
        logger.error(
            "Telethon not installed. Run: pip install telethon"
        )
        return False
    return True


class TelegramMTProtoAdapter(BasePlatformAdapter):
    """
    Telegram adapter using MTProto via Telethon.

    Operates as a user account, not a bot. This enables:
    - Initiating DMs with any user
    - No privacy mode restrictions in groups
    - Larger file uploads
    - Full user presence
    """

    name = "telegram-mtproto"

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.TELEGRAM_MTPROTO)

        # Telethon client
        self._client: Optional[TelegramClient] = None

        # Auth credentials
        self._api_id = int(config.extra.get("api_id", os.getenv("TELEGRAM_MTPROTO_API_ID", "0")))
        self._api_hash = config.extra.get("api_hash", os.getenv("TELEGRAM_MTPROTO_API_HASH", ""))
        self._phone = config.extra.get("phone", os.getenv("TELEGRAM_MTPROTO_PHONE", ""))
        self._session_path = config.extra.get(
            "session_path",
            os.getenv("TELEGRAM_MTPROTO_SESSION_PATH", "./data/telegram-mtproto/session"),
        )

        # Identity (populated on connect)
        self._my_user_id: Optional[int] = None
        self._my_username: Optional[str] = None

        # Group policy
        self._group_policy: GroupPolicy = config.extra.get(
            "group_policy",
            os.getenv("TELEGRAM_MTPROTO_GROUP_POLICY", "both"),
        )

        # Admin chat for pairing notifications
        self._admin_chat_id: Optional[int] = None
        admin_id = config.extra.get("admin_chat_id", os.getenv("TELEGRAM_MTPROTO_ADMIN_CHAT_ID"))
        if admin_id:
            self._admin_chat_id = int(admin_id)

        # Track sent messages for reply detection in groups
        self._sent_message_ids: set[int] = set()

        # Event handler reference for cleanup
        self._message_handler_ref = None

    # ==================== Lifecycle ====================

    async def connect(self) -> bool:
        """Connect to Telegram via MTProto and start receiving messages."""
        if not TELETHON_AVAILABLE:
            logger.error("[%s] Telethon not installed", self.name)
            return False

        if not self._api_id or not self._api_hash:
            logger.error("[%s] Missing api_id or api_hash", self.name)
            return False

        if not self._phone:
            logger.error("[%s] Missing phone number", self.name)
            return False

        try:
            # Ensure session directory exists
            session_dir = os.path.dirname(self._session_path)
            if session_dir:
                os.makedirs(session_dir, exist_ok=True)

            # Create Telethon client
            self._client = TelegramClient(
                self._session_path,
                self._api_id,
                self._api_hash,
            )

            # Start client (handles auth if session doesn't exist)
            # On first run, this will prompt for verification code
            await self._client.start(phone=self._phone)

            # Get our identity
            me = await self._client.get_me()
            self._my_user_id = me.id
            self._my_username = me.username
            logger.info(
                "[%s] Authenticated as %s (ID: %s)",
                self.name,
                self._my_username or "unknown",
                self._my_user_id,
            )

            # Register message handler
            self._message_handler_ref = self._on_new_message
            self._client.add_event_handler(
                self._message_handler_ref,
                events.NewMessage(),
            )

            self._mark_connected()
            logger.info("[%s] Connected and listening", self.name)
            return True

        except Exception as e:
            logger.error("[%s] Failed to connect: %s", self.name, e)
            self._set_fatal_error(
                "CONNECT_FAILED",
                str(e),
                retryable=True,
            )
            return False

    async def disconnect(self) -> None:
        """Disconnect from Telegram."""
        logger.info("[%s] Disconnecting...", self.name)

        # Remove event handler
        if self._client and self._message_handler_ref:
            self._client.remove_event_handler(self._message_handler_ref)
            self._message_handler_ref = None

        # Cancel background tasks
        for task in list(self._background_tasks):
            if not task.done():
                self._expected_cancelled_tasks.add(task)
                task.cancel()
        self._background_tasks.clear()

        # Disconnect client (keeps session file for reconnect)
        if self._client:
            try:
                await self._client.disconnect()
            except Exception as e:
                logger.warning("[%s] Error during disconnect: %s", self.name, e)
            self._client = None

        self._mark_disconnected()
        logger.info("[%s] Disconnected", self.name)

    # ==================== Inbound Messages ====================

    async def _on_new_message(self, event: "events.NewMessage.Event") -> None:
        """Handle incoming Telethon message event."""
        try:
            message = event.message

            # Skip outgoing messages
            if message.out:
                # Track for reply detection
                self._track_sent_message(message.id)
                return

            # Skip if no message handler registered
            if not self._message_handler:
                return

            # Get sender — must be a user
            sender = await message.get_sender()
            if not sender or not isinstance(sender, User):
                return

            # Skip bots
            if sender.bot:
                return

            user_id = str(sender.id)
            chat = await message.get_chat()
            chat_id = str(message.chat_id)

            # Determine if group
            is_group = isinstance(chat, (Chat, Channel)) and not getattr(chat, "broadcast", False)

            # Apply group policy
            if is_group:
                if not self._should_respond_in_group(message):
                    return

            # Skip admin chat (only pairing replies handled, not implemented yet)
            if self._admin_chat_id and message.chat_id == self._admin_chat_id:
                return

            # Get text content
            text = message.text or ""
            if not text:
                return

            # Build username
            username = sender.username or sender.first_name or user_id

            # Determine chat type
            if is_group:
                chat_type = "group"
            else:
                chat_type = "dm"

            # Build chat name
            if is_group:
                chat_name = getattr(chat, "title", None) or chat_id
            else:
                chat_name = username

            # Create MessageEvent
            msg_event = MessageEvent(
                chat_id=chat_id,
                user_id=user_id,
                username=username,
                text=text,
                message_id=str(message.id),
                message_type=MessageType.TEXT,
                timestamp=message.date or datetime.now(timezone.utc),
                source=self.build_source(
                    chat_id=chat_id,
                    user_id=user_id,
                    username=username,
                    chat_type=chat_type,
                    chat_name=chat_name,
                    platform_name=self.name,
                ),
            )

            # Dispatch to gateway
            await self.handle_message(msg_event)

        except Exception as e:
            logger.error("[%s] Error handling message: %s", self.name, e, exc_info=True)

    # ==================== Outbound Messages ====================

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a text message."""
        if not self._client:
            return SendResult(success=False, error="Client not connected")

        try:
            # Truncate if needed
            if len(content) > MAX_MESSAGE_LENGTH:
                content = content[:MAX_MESSAGE_LENGTH - 3] + "..."

            reply_to_id = int(reply_to) if reply_to else None

            result = await self._client.send_message(
                int(chat_id),
                content,
                parse_mode="md",
                reply_to=reply_to_id,
                link_preview=False,
            )

            self._track_sent_message(result.id)

            return SendResult(
                success=True,
                message_id=str(result.id),
            )

        except Exception as e:
            logger.error("[%s] Failed to send message: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Edit a previously sent message."""
        if not self._client:
            return SendResult(success=False, error="Client not connected")

        try:
            await self._client.edit_message(
                int(chat_id),
                int(message_id),
                content,
                parse_mode="md",
                link_preview=False,
            )
            return SendResult(success=True, message_id=message_id)

        except Exception as e:
            logger.error("[%s] Failed to edit message: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def send_typing(
        self,
        chat_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Send typing indicator."""
        if not self._client:
            return

        try:
            await self._client(SetTypingRequest(
                peer=int(chat_id),
                action=SendMessageTypingAction(),
            ))
        except Exception:
            pass  # Best-effort

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an image from URL."""
        if not self._client:
            return SendResult(success=False, error="Client not connected")

        try:
            result = await self._client.send_file(
                int(chat_id),
                image_url,
                caption=caption,
                parse_mode="md",
            )
            self._track_sent_message(result.id)
            return SendResult(success=True, message_id=str(result.id))

        except Exception as e:
            logger.error("[%s] Failed to send image: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def send_image_file(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an image from local file."""
        if not self._client:
            return SendResult(success=False, error="Client not connected")

        try:
            result = await self._client.send_file(
                int(chat_id),
                file_path,
                caption=caption,
                parse_mode="md",
                force_document=False,
            )
            self._track_sent_message(result.id)
            return SendResult(success=True, message_id=str(result.id))

        except Exception as e:
            logger.error("[%s] Failed to send image file: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a document/file."""
        if not self._client:
            return SendResult(success=False, error="Client not connected")

        try:
            result = await self._client.send_file(
                int(chat_id),
                file_path,
                caption=caption,
                parse_mode="md",
                force_document=True,
            )
            self._track_sent_message(result.id)
            return SendResult(success=True, message_id=str(result.id))

        except Exception as e:
            logger.error("[%s] Failed to send document: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def send_voice(
        self,
        chat_id: str,
        file_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a voice message."""
        if not self._client:
            return SendResult(success=False, error="Client not connected")

        try:
            result = await self._client.send_file(
                int(chat_id),
                file_path,
                voice_note=True,
            )
            self._track_sent_message(result.id)
            return SendResult(success=True, message_id=str(result.id))

        except Exception as e:
            logger.error("[%s] Failed to send voice: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    # ==================== Chat Info ====================

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Get information about a chat."""
        if not self._client:
            return {"name": chat_id, "type": "unknown", "chat_id": chat_id}

        try:
            entity = await self._client.get_entity(int(chat_id))

            if isinstance(entity, User):
                name = entity.username or entity.first_name or str(entity.id)
                chat_type = "dm"
            elif isinstance(entity, Channel):
                name = entity.title or str(entity.id)
                chat_type = "channel" if entity.broadcast else "group"
            elif isinstance(entity, Chat):
                name = entity.title or str(entity.id)
                chat_type = "group"
            else:
                name = str(chat_id)
                chat_type = "unknown"

            return {
                "name": name,
                "type": chat_type,
                "chat_id": chat_id,
            }

        except Exception as e:
            logger.warning("[%s] Could not get chat info for %s: %s", self.name, chat_id, e)
            return {"name": chat_id, "type": "unknown", "chat_id": chat_id}

    # ==================== User API (for tools) ====================

    async def get_user_info(self, user_id: int) -> Dict[str, Any]:
        """Get public user info."""
        if not self._client:
            raise RuntimeError("Client not connected")

        user = await self._client.get_entity(user_id)
        if not isinstance(user, User):
            raise ValueError(f"{user_id} is not a user")

        return {
            "user_id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
        }

    async def search_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Search for a user by username."""
        if not self._client:
            raise RuntimeError("Client not connected")

        clean = username.lstrip("@")
        try:
            entity = await self._client.get_entity(clean)
            if isinstance(entity, User):
                return {
                    "user_id": entity.id,
                    "username": entity.username,
                    "first_name": entity.first_name,
                }
            return None
        except Exception:
            return None

    async def initiate_dm(self, user_id: int, text: str) -> Dict[str, str]:
        """Send a DM to a user (can initiate first contact)."""
        if not self._client:
            raise RuntimeError("Client not connected")

        result = await self._client.send_message(
            user_id,
            text,
            parse_mode="md",
            link_preview=False,
        )

        self._track_sent_message(result.id)

        return {
            "chat_id": str(result.chat_id),
            "message_id": str(result.id),
        }

    # ==================== Group Policy ====================

    def _should_respond_in_group(self, message) -> bool:
        """Apply group policy to determine if we should respond."""
        policy = self._group_policy

        if policy == "off":
            return False

        mentioned = self._is_mentioned(message)
        is_reply = self._is_reply_to_us(message)

        if policy == "mention":
            return mentioned
        elif policy == "reply":
            return is_reply
        else:  # 'both' (default)
            return mentioned or is_reply

    def _is_mentioned(self, message) -> bool:
        """Check if we are mentioned in the message."""
        if not self._my_user_id:
            return False

        if not message.entities:
            return False

        for entity in message.entities:
            if isinstance(entity, MessageEntityMention):
                # Extract @username from text
                mention_text = message.text[entity.offset:entity.offset + entity.length]
                if self._my_username and mention_text.lower() == f"@{self._my_username.lower()}":
                    return True
            elif isinstance(entity, MessageEntityMentionName):
                if entity.user_id == self._my_user_id:
                    return True

        return False

    def _is_reply_to_us(self, message) -> bool:
        """Check if the message is a reply to one of our messages."""
        if not message.reply_to:
            return False
        reply_id = message.reply_to.reply_to_msg_id
        return reply_id in self._sent_message_ids

    # ==================== Helpers ====================

    def _track_sent_message(self, message_id: int) -> None:
        """Track a sent message ID for reply detection."""
        self._sent_message_ids.add(message_id)
        # Cap at 1000 to prevent memory leak
        if len(self._sent_message_ids) > 1000:
            # Remove oldest 100
            it = iter(self._sent_message_ids)
            for _ in range(100):
                self._sent_message_ids.discard(next(it))
