"""Explicit opt-in only; inert input and no model installation."""
import os
import pytest
from orgscan.config import Settings
from orgscan.ai.ollama import OllamaProvider

@pytest.mark.skipif(os.environ.get('ORGSCAN_RUN_LIVE_OLLAMA_TESTS')!='1',reason='Optional local Ollama smoke is disabled')
def test_live_ollama():
    settings=Settings()
    provider=OllamaProvider(settings,settings.ollama_base_url,settings.ollama_model)
    assert provider.health()['status']=='ready'
    assert provider.list_models()
    assert provider.generate('Summarize this inert synthetic metadata: one public documentation repository, no findings.')['explanation']
