import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from som_api.providers.hillstone import UnconfiguredHillstoneProvider

@pytest.mark.asyncio
async def test_provider_is_honestly_unconfigured():
    with pytest.raises(RuntimeError,match='no configurado'):
        await UnconfiguredHillstoneProvider('WAF').authenticate()
