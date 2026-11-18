import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from scripts.aegis_agent import investigate
from scripts.aegis_investigation import correlate
from test_investigation import hit


def reply(content=None, tools=None):
    return {"model": "test-model", "usage": {"total_tokens": 20}, "choices": [{"message": {
        "role": "assistant", "content": content, **({"tool_calls": tools} if tools else {})}}]}


def tool(name="read_incident_evidence", arguments="{}"):
    return {"id": "call-1", "type": "function", "function": {"name": name, "arguments": arguments}}


class AgentTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.incident = correlate([hit()])[0][0]
        self.env = patch.dict("os.environ", {"AEGIS_LLM_BASE_URL": "http://test/v1", "AEGIS_LLM_MODEL": "test-model"})
        self.env.start()

    async def asyncTearDown(self):
        self.env.stop()

    def decision(self, references=None):
        return json.dumps({"assessment": "suspicious", "summary": "Review this rule match.",
                           "evidence_ids": references or ["aegis-alerts-default:1"],
                           "missing_evidence": ["Authorization"], "recommended_checks": ["Review endpoint"]})

    async def test_grounded_tool_loop(self):
        complete = AsyncMock(side_effect=[reply(tools=[tool()]), reply(self.decision())])
        result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), complete)
        self.assertEqual(result["agent_status"], "completed")
        self.assertEqual(result["engine"], "llm-agent-v1")
        self.assertEqual(result["verdict"], "needs_review")
        self.assertFalse(result["response"]["executed"])
        self.assertEqual(result["agent_steps"][0]["requested_by"], "server")
        self.assertTrue(any(step.get("requested_by") == "model" for step in result["agent_steps"]))

    async def test_hallucinated_reference_demotes_to_baseline(self):
        complete = AsyncMock(side_effect=[reply(tools=[tool()]), reply(self.decision(["invented:reference"]))])
        result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), complete)
        self.assertEqual(result["agent_status"], "failed")
        self.assertEqual(result["engine"], "deterministic-v1")
        self.assertIsNone(result["model"])

    async def test_prerequisite_evidence_supports_direct_json_response(self):
        complete = AsyncMock(return_value=reply(self.decision()))
        result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), complete)
        self.assertEqual(result["agent_status"], "completed")
        self.assertEqual(result["agent_steps"][0]["requested_by"], "server")
        messages = complete.call_args.args[0]
        supplied = json.loads(messages[1]["content"])["prerequisite_evidence"]["evidence"]
        self.assertEqual(supplied[0]["evidence_id"], "aegis-alerts-default:1")

    async def test_unknown_tool_or_model_selected_arguments_fail(self):
        for response in [reply(tools=[tool("run_command")]),
                         reply(tools=[tool(arguments='{"query":"*"}')])]:
            result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), AsyncMock(return_value=response))
            self.assertEqual(result["agent_status"], "failed")

    async def test_cannot_cite_server_sample_not_supplied_to_model(self):
        context = {"evidence": [{"evidence_id": "logs-other:neighbor", "event": {"process": {"name": "other.exe"}}}], "partial": True}
        complete = AsyncMock(return_value=reply(self.decision(["logs-other:neighbor"])))
        result = await investigate(self.incident, AsyncMock(return_value=context), complete)
        self.assertEqual(result["agent_status"], "failed")
        self.assertEqual(result["context_summary"]["examined_events"], 1)
        self.assertEqual(result["context_summary"]["model_evidence_count"], 0)
        sent = json.loads(complete.call_args.args[0][1]["content"])["host_context"]["evidence"]
        self.assertEqual(sent, [])

    async def test_budget_is_bounded(self):
        complete = AsyncMock(return_value=reply(tools=[tool()]))
        result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), complete)
        self.assertEqual(complete.await_count, 4)
        self.assertEqual(result["agent_status"], "failed")

    async def test_provider_failure_and_missing_configuration(self):
        result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), AsyncMock(side_effect=httpx.ConnectError("secret provider response")))
        self.assertEqual(result["agent_status"], "failed")
        self.assertNotIn("secret", json.dumps(result))
        with patch.dict("os.environ", {"AEGIS_LLM_MODEL": ""}):
            complete = AsyncMock()
            result = await investigate(self.incident, AsyncMock(return_value={"evidence": [], "partial": False}), complete)
            self.assertEqual(result["agent_status"], "not_configured")
            complete.assert_not_called()
