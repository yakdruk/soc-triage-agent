"""Vertex AI Memory Bank service integration for SOC triage agent.

Provides durable, cross-session long-term memory using Google Cloud Agent Platform.
"""

import os
import vertexai
from google.adk.memory import VertexAiMemoryBankService

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
DEFAULT_MEMORY_BANK_ID = os.environ.get("MEMORY_BANK_ID", "")


class SOCMemoryBankService(VertexAiMemoryBankService):
    """Memory service with a persistent vertexai.Client connection to prevent premature closure."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_client = vertexai.Client(
            project=self._project,
            location=self._location,
            credentials=self._credentials,
        )

    def _get_api_client(self):
        return self._cached_client.aio


def get_memory_service(memory_bank_id: str | None = None) -> SOCMemoryBankService:
    """Return a configured Memory Bank service instance."""
    engine_id = memory_bank_id or os.environ.get("MEMORY_BANK_ID") or DEFAULT_MEMORY_BANK_ID
    return SOCMemoryBankService(
        project=PROJECT_ID,
        location=LOCATION,
        agent_engine_id=engine_id,
    )
