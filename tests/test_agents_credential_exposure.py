import pytest

from noctis.agents.credential_exposure import CredentialExposureAgent
from test_agents_common import build_context


@pytest.mark.asyncio
async def test_confirms_secret_still_present(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text("DEBUG = True\nAWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n", encoding="utf-8")

    node_data = {"type": "secret", "file": "config.py", "line": 2, "kind": "aws_access_key", "masked_value": "AKIA****MNOP"}
    context = build_context(tmp_path, node_data)
    context.repo_path = str(repo)

    agent = CredentialExposureAgent(context)
    result = await agent.execute()

    assert result.found is True
    assert "AWS_KEY" in result.response


@pytest.mark.asyncio
async def test_no_finding_when_file_missing(tmp_path):
    node_data = {"type": "secret", "file": "gone.py", "line": 1, "kind": "generic_api_key", "masked_value": "abcd****wxyz"}
    context = build_context(tmp_path, node_data)
    context.repo_path = str(tmp_path)

    agent = CredentialExposureAgent(context)
    result = await agent.execute()

    assert result.found is False
