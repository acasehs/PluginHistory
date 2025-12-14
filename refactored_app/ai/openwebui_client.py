"""
OpenWebUI Client
Handles API communication with OpenWebUI for AI predictions.
Supports both Ollama and AWS Bedrock backends managed through OpenWebUI.
"""

import requests
import threading
import json
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time


class ConnectionStatus(Enum):
    """OpenWebUI connection status."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class OpenWebUIConfig:
    """OpenWebUI connection configuration."""
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.15  # Deterministic default
    max_tokens: int = 8000
    timeout: int = 300  # 5 minutes for large analyses

    def is_configured(self) -> bool:
        """Check if minimum configuration is present."""
        return bool(self.base_url and self.api_key)


@dataclass
class ChatMessage:
    """Single message in a conversation."""
    role: str  # "user", "assistant", "system"
    content: str


@dataclass
class ChatResponse:
    """Response from OpenWebUI chat completion."""
    success: bool
    content: str = ""
    error: str = ""
    model: str = ""
    usage: Dict[str, int] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)


class OpenWebUIClient:
    """
    Client for OpenWebUI API interactions.
    Handles model discovery, chat completions, and RAG integration.
    """

    def __init__(self, config: Optional[OpenWebUIConfig] = None):
        """Initialize client with optional configuration."""
        self.config = config or OpenWebUIConfig()
        self._available_models: List[str] = []
        self._available_collections: List[Dict[str, str]] = []
        self._status = ConnectionStatus.DISCONNECTED
        self._status_message = ""
        self._lock = threading.Lock()
        self._status_callbacks: List[Callable[[ConnectionStatus, str], None]] = []

    @property
    def status(self) -> ConnectionStatus:
        """Get current connection status."""
        return self._status

    @property
    def status_message(self) -> str:
        """Get current status message."""
        return self._status_message

    @property
    def available_models(self) -> List[str]:
        """Get list of available models."""
        with self._lock:
            return self._available_models.copy()

    @property
    def available_collections(self) -> List[Dict[str, str]]:
        """Get list of available RAG collections."""
        with self._lock:
            return self._available_collections.copy()

    def add_status_callback(self, callback: Callable[[ConnectionStatus, str], None]):
        """Add callback for status changes."""
        self._status_callbacks.append(callback)

    def _set_status(self, status: ConnectionStatus, message: str = ""):
        """Update status and notify callbacks."""
        self._status = status
        self._status_message = message
        for callback in self._status_callbacks:
            try:
                callback(status, message)
            except Exception:
                pass  # Don't let callback errors break the client

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        return {
            'Authorization': f'Bearer {self.config.api_key}',
            'Content-Type': 'application/json'
        }

    def test_connection(self) -> bool:
        """
        Test connection to OpenWebUI.
        Returns True if connection successful.
        """
        if not self.config.is_configured():
            self._set_status(ConnectionStatus.ERROR, "Not configured")
            return False

        self._set_status(ConnectionStatus.CONNECTING, "Testing connection...")

        try:
            response = requests.get(
                f"{self.config.base_url}/api/models",
                headers=self._get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                self._set_status(ConnectionStatus.CONNECTED, "Connected")
                return True
            elif response.status_code == 401:
                self._set_status(ConnectionStatus.ERROR, "Invalid API key")
                return False
            else:
                self._set_status(
                    ConnectionStatus.ERROR,
                    f"HTTP {response.status_code}: {response.text[:100]}"
                )
                return False

        except requests.exceptions.Timeout:
            self._set_status(ConnectionStatus.ERROR, "Connection timed out")
            return False
        except requests.exceptions.ConnectionError as e:
            self._set_status(ConnectionStatus.ERROR, f"Connection failed: {str(e)[:50]}")
            return False
        except Exception as e:
            self._set_status(ConnectionStatus.ERROR, f"Error: {str(e)[:50]}")
            return False

    def refresh_models(self) -> List[str]:
        """
        Refresh available models list synchronously.
        Returns list of model IDs.
        """
        if not self.config.is_configured():
            return []

        try:
            response = requests.get(
                f"{self.config.base_url}/api/models",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                models = []

                # Handle different response formats
                if isinstance(data, dict) and 'data' in data:
                    models_list = data['data']
                elif isinstance(data, list):
                    models_list = data
                else:
                    models_list = [data] if data else []

                for model in models_list:
                    if isinstance(model, dict):
                        model_id = model.get('id', model.get('name', 'unknown'))
                        models.append(model_id)
                    else:
                        models.append(str(model))

                with self._lock:
                    self._available_models = models

                return models

        except Exception as e:
            print(f"Error refreshing models: {e}")

        return []

    def refresh_models_async(
        self,
        callback: Optional[Callable[[List[str], Optional[str]], None]] = None
    ):
        """
        Refresh available models asynchronously (non-blocking).

        Args:
            callback: Optional callback(models, error) called when complete.
                     models is list of model IDs, error is None on success.
        """
        def _fetch():
            try:
                models = self.refresh_models()
                if callback:
                    callback(models, None)
            except Exception as e:
                if callback:
                    callback([], str(e))

        thread = threading.Thread(target=_fetch, daemon=True)
        thread.start()

    def refresh_collections(self) -> List[Dict[str, str]]:
        """
        Refresh available RAG knowledge collections.
        Returns list of collection info dicts with 'id' and 'name'.
        """
        if not self.config.is_configured():
            return []

        try:
            response = requests.get(
                f"{self.config.base_url}/api/v1/knowledge",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                collections = []

                # Handle response format
                items = data if isinstance(data, list) else data.get('data', [])

                for item in items:
                    if isinstance(item, dict):
                        collections.append({
                            'id': item.get('id', ''),
                            'name': item.get('name', item.get('id', 'Unknown')),
                            'description': item.get('description', '')
                        })

                with self._lock:
                    self._available_collections = collections

                return collections

        except Exception as e:
            print(f"Error refreshing collections: {e}")

        return []

    def refresh_collections_async(
        self,
        callback: Optional[Callable[[List[Dict[str, str]], Optional[str]], None]] = None
    ):
        """
        Refresh collections asynchronously (non-blocking).
        """
        def _fetch():
            try:
                collections = self.refresh_collections()
                if callback:
                    callback(collections, None)
            except Exception as e:
                if callback:
                    callback([], str(e))

        thread = threading.Thread(target=_fetch, daemon=True)
        thread.start()

    def chat_completion(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        collection_ids: Optional[List[str]] = None,
        system_prompt: Optional[str] = None
    ) -> ChatResponse:
        """
        Send chat completion request to OpenWebUI.

        Args:
            messages: List of chat messages
            model: Model to use (defaults to config.model)
            temperature: Temperature setting (defaults to config, rounded to 0.01)
            max_tokens: Max tokens (defaults to config.max_tokens)
            collection_ids: Optional RAG collection IDs to include
            system_prompt: Optional system prompt to prepend

        Returns:
            ChatResponse with result or error
        """
        if not self.config.is_configured():
            return ChatResponse(
                success=False,
                error="OpenWebUI not configured"
            )

        # Use provided values or defaults
        use_model = model or self.config.model
        use_temp = round(temperature if temperature is not None else self.config.temperature, 2)
        use_tokens = max_tokens or self.config.max_tokens

        if not use_model:
            return ChatResponse(
                success=False,
                error="No model selected"
            )

        # Build messages list
        api_messages = []

        # Add system prompt if provided
        if system_prompt:
            api_messages.append({
                "role": "system",
                "content": system_prompt
            })

        # Add conversation messages
        for msg in messages:
            api_messages.append({
                "role": msg.role,
                "content": msg.content
            })

        # Build payload
        payload = {
            "model": use_model,
            "messages": api_messages,
            "stream": False,
            "temperature": use_temp,
            "max_tokens": use_tokens
        }

        # Add RAG collections if specified
        if collection_ids:
            payload["files"] = [
                {"type": "collection", "id": cid}
                for cid in collection_ids
            ]

        try:
            response = requests.post(
                f"{self.config.base_url}/api/chat/completions",
                headers=self._get_headers(),
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                result = response.json()

                # Extract content from response
                content = ""
                if 'choices' in result and len(result['choices']) > 0:
                    content = result['choices'][0].get('message', {}).get('content', '')
                elif 'response' in result:
                    content = result['response']

                if not content:
                    return ChatResponse(
                        success=False,
                        error="Empty response from model",
                        raw_response=result
                    )

                return ChatResponse(
                    success=True,
                    content=content,
                    model=use_model,
                    usage=result.get('usage', {}),
                    raw_response=result
                )

            else:
                return ChatResponse(
                    success=False,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                    model=use_model
                )

        except requests.exceptions.Timeout:
            return ChatResponse(
                success=False,
                error=f"Request timed out after {self.config.timeout} seconds",
                model=use_model
            )
        except requests.exceptions.ConnectionError as e:
            return ChatResponse(
                success=False,
                error=f"Connection error: {str(e)[:100]}",
                model=use_model
            )
        except Exception as e:
            return ChatResponse(
                success=False,
                error=f"Unexpected error: {str(e)[:100]}",
                model=use_model
            )

    def simple_query(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        collection_ids: Optional[List[str]] = None,
        system_prompt: Optional[str] = None
    ) -> ChatResponse:
        """
        Simple single-turn query helper.

        Args:
            prompt: User prompt to send
            model: Optional model override
            temperature: Optional temperature override
            collection_ids: Optional RAG collections
            system_prompt: Optional system prompt

        Returns:
            ChatResponse with result
        """
        messages = [ChatMessage(role="user", content=prompt)]
        return self.chat_completion(
            messages=messages,
            model=model,
            temperature=temperature,
            collection_ids=collection_ids,
            system_prompt=system_prompt
        )

    def query_with_conversation(
        self,
        conversation_history: List[Dict[str, str]],
        new_message: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        collection_ids: Optional[List[str]] = None,
        system_prompt: Optional[str] = None
    ) -> ChatResponse:
        """
        Query with existing conversation context (for follow-up questions).

        Args:
            conversation_history: List of prior messages [{"role": "...", "content": "..."}]
            new_message: New user message to add
            model: Optional model override
            temperature: Optional temperature override
            collection_ids: Optional RAG collections
            system_prompt: Optional system prompt

        Returns:
            ChatResponse with result
        """
        messages = [
            ChatMessage(role=msg['role'], content=msg['content'])
            for msg in conversation_history
        ]
        messages.append(ChatMessage(role="user", content=new_message))

        return self.chat_completion(
            messages=messages,
            model=model,
            temperature=temperature,
            collection_ids=collection_ids,
            system_prompt=system_prompt
        )

    def get_collection_by_name(self, name: str) -> Optional[Dict[str, str]]:
        """Find a collection by name."""
        for collection in self._available_collections:
            if collection.get('name') == name:
                return collection
        return None

    def is_model_available(self, model_id: str) -> bool:
        """Check if a specific model is available."""
        return model_id in self._available_models
