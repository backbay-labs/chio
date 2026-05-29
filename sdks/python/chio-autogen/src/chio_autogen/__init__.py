"""Chio AutoGen integration.

Wraps AutoGen's ``register_function`` / ``function_map`` and
``GroupChat`` / ``GroupChatManager`` so every registered function call
flows through the Chio sidecar for capability-scoped authorization and
signed receipts.

Public surface:

* :class:`ChioFunctionRegistry` -- per-agent registry that wraps each
  registered function with a Chio allow gate.
* :class:`ChioGroupChat` / :class:`ChioGroupChatManager` -- subclasses
  of :class:`autogen.GroupChat` / :class:`autogen.GroupChatManager`
  that accept a per-role ``capability_scope`` mapping.
* :func:`register_nested_chats_with_attenuation` -- mints attenuated
  child capabilities for nested conversations.
* :class:`ChioToolError` / :class:`ChioAutogenConfigError` -- error
  types.
"""

from chio_autogen.errors import ChioAutogenConfigError, ChioToolError
from chio_autogen.functions import (
    ChioFunctionRegistry,
    attach_registry,
    registry_for,
)
from chio_autogen.group_chat import ChioGroupChat, ChioGroupChatManager
from chio_autogen.nested import (
    attenuate_for_initiate_chats,
    rebind_registries,
    register_nested_chats_with_attenuation,
)

__all__ = [
    "ChioAutogenConfigError",
    "ChioFunctionRegistry",
    "ChioGroupChat",
    "ChioGroupChatManager",
    "ChioToolError",
    "attach_registry",
    "attenuate_for_initiate_chats",
    "rebind_registries",
    "register_nested_chats_with_attenuation",
    "registry_for",
]
