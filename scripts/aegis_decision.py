"""Parse provider JSON, normalize presentation limits, preserve citation validation."""
import json
from pydantic import ValidationError


class DecisionError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def parse_decision(content, schema, allowed, aliases=None, finish_reason=None):
    if not isinstance(content, str) or not content.strip():
        raise DecisionError('empty_response', 'The model returned no decision text.')
    text = content.strip()
    if text.startswith('```') and text.endswith('```'):
        text = text.split('\n', 1)[-1].rsplit('```', 1)[0].strip()
    try:
        data = json.loads(text)
    except ValueError as exc:
        code = 'output_truncated' if finish_reason == 'length' else 'invalid_json'
        raise DecisionError(code, 'Model output reached the token limit before completing JSON.' if code == 'output_truncated' else 'The model returned malformed JSON.') from exc
    if not isinstance(data, dict):
        raise DecisionError('invalid_schema', 'The model decision must be a JSON object.')
    warnings = []
    references = data.get('evidence_ids')
    if isinstance(references, list) and all(isinstance(ref, str) for ref in references):
        mapped = [(aliases or {}).get(ref, ref) for ref in references]
        # Validate every reference BEFORE trimming; overflow must never hide hallucinated IDs.
        if not set(mapped).issubset(allowed):
            raise DecisionError('unknown_reference', 'The model cited evidence that was not provided.')
        data['evidence_ids'] = mapped
    for field, limit in [('evidence_ids', 3), ('missing_evidence', 10), ('recommended_checks', 3)]:
        values = data.get(field)
        if isinstance(values, list) and all(isinstance(item, str) for item in values):
            normalized = list(dict.fromkeys(values))[:limit]
            if normalized != values:
                warnings.append(field + '_deduplicated_or_limited')
            data[field] = normalized
    if isinstance(data.get('summary'), str) and len(data['summary']) > 2000:
        data['summary'] = data['summary'][:1997] + '...'
        warnings.append('summary_limited')
    try:
        return schema.model_validate(data), warnings
    except ValidationError as exc:
        fields = ', '.join(sorted({str(e['loc'][0]) for e in exc.errors() if e['loc']}))
        raise DecisionError('invalid_schema', 'Model output has missing or invalid fields: ' + fields) from exc
