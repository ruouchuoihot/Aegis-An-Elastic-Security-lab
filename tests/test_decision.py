import json
import unittest
from scripts.aegis_agent import AgentDecision
from scripts.aegis_decision import DecisionError, parse_decision


class DecisionTests(unittest.TestCase):
    def decision(self, **changes):
        return {'assessment':'inconclusive','summary':'Discovery observed; intent remains uncertain.',
                'evidence_ids':['E1'],'missing_evidence':[],'recommended_checks':[],**changes}

    def test_valid_long_lists_are_normalized_with_audit_warning(self):
        content = self.decision(missing_evidence=[f'gap-{i}' for i in range(22)])
        decision, warnings = parse_decision(json.dumps(content),AgentDecision,{'alerts:1'},{'E1':'alerts:1'})
        self.assertEqual(decision.evidence_ids,['alerts:1'])
        self.assertEqual(len(decision.missing_evidence),10)
        self.assertIn('missing_evidence_deduplicated_or_limited',warnings)

    def test_unknown_id_after_limit_still_fails(self):
        content = self.decision(evidence_ids=['E1','E1','E1','invented'])
        with self.assertRaises(DecisionError) as cm:
            parse_decision(json.dumps(content),AgentDecision,{'alerts:1'},{'E1':'alerts:1'})
        self.assertEqual(cm.exception.code,'unknown_reference')

    def test_truncation_is_reported_without_fabricating_missing_json(self):
        with self.assertRaises(DecisionError) as cm:
            parse_decision('{"assessment":"inconclusive","summary":"unfinished',AgentDecision,set(),finish_reason='length')
        self.assertEqual(cm.exception.code,'output_truncated')

    def test_invalid_assessment_is_not_coerced(self):
        with self.assertRaises(DecisionError) as cm:
            parse_decision(json.dumps(self.decision(assessment='definitely_hacked')),AgentDecision,{'E1'})
        self.assertEqual(cm.exception.code,'invalid_schema')
