# Session Retrospective v2 Agent Prompts

The automation coordinator launches native ephemeral subagents at the maximum
available concurrency. SSH and source transport remain serial per host. Agents
receive one bounded job manifest and must return one JSON document matching the
job's declared schema.

## Extractor And Redactor

```text
Read only the bounded shard supplied by the deterministic supervisor.
Extract meaningful collaboration evidence turn by turn. Ignore wrappers,
injected policy text, automation boilerplate, heartbeats, and synthetic review
prompts. Redact secrets, credentials, personal/customer identifiers, internal
URLs, local paths, raw IDs, proprietary snippets, original prompts, and tool
output before emitting any field.

Return only the declared extractor_result_v2 JSON object. Use closed event,
finding, strength, risk, and outcome enums. Do not emit excerpts or substitute
invented detail. When evidence is insufficient, emit an explicit confidence or
coverage gap.
```

## Episode Reviewer

```text
Review exactly one validated redacted episode revision. Assess what happened,
what worked, friction/confusion, errors and verification, collaboration pattern,
safety/privacy, prompt improvements, durable guidance evidence, reusable skill
candidates, and follow-up actions. Record strengths separately from findings.

For every high-impact turn, return the issue, why it mattered, a rewritten user
prompt, expected effect, confidence, and opaque evidence references. Do not quote
the turn. Return only episode_review_result_v2 JSON.

For a hierarchical review input, bind the supplied child hashes and preserve all
high/critical events and findings, every high-impact rewrite, risk flag, evidence
reference, escalation/conflict decision, and the lowest child confidence. Never
summarize away a child risk decision.
```

## Independent Risk Review And Adjudication

```text
Independently review the same validated redacted episode without seeing the
first review. Use only closed risk/finding taxonomies and opaque evidence refs.
If this is an adjudication job, compare the two supplied structured decisions,
resolve only supported conflicts, and account for every candidate event,
finding, strength, risk flag, high-impact rewrite, and evidence reference in
slot order. Mark each item selected, merged, or explicitly rejected with a
closed reason and its exact candidate hash, reviewer, and attempt provenance.
Preserve the complete decision trace and both validated candidates downstream.
Emit an explicit review gap when no supported resolution exists. Preserve every
independently reported high- or critical-severity secondary event or finding; a
review gap may retain uncertainty but must not omit that risk. Return only the
declared JSON schema.
```

## Topic Reducer

```text
Reduce the bounded set of validated episode-review revisions for one stable
workstream/topic candidate. Preserve episode-level disagreements and evidence
references, including every high- or critical-severity event or finding. Produce
cross-thread recurrence, strengths, friction, prompt
improvements, guidance/skill candidates, open work, and confidence. Never create
new source evidence or merge incompatible model/policy eras. Leaf inputs are
already below the per-result limit; hierarchical inputs contain only validated
child results and their exact hashes. Return only topic_review_result_v2 JSON.
```

## Global Synthesis

```text
Synthesize only validated topic results and aggregate coverage metadata. Answer
the ten retrospective questions, strengths, four confidence dimensions, and
compatible-era changes. Preserve every high- or critical-severity event or
finding from validated topic results. Bind every canonical topic signal with the
provided exact count/hash commitment and emit only the deterministic bounded
exemplars. Durable AGENTS.md or Skill candidates must cite exact episode/session
pairs for at least three episodes across two actual sessions unless one
independently reviewed high-severity safety event qualifies for the exception.
Return only global_synthesis_result_v2 JSON.
```

The coordinator admits global synthesis only after exactly one accepted final
topic result exists for every expected topic-input root. Missing, duplicate, or
extra roots are not model-repairable and block before synthesis.

Invalid JSON, schema mismatch, reference injection, privacy rejection, crash, or
timeout causes one retry in a fresh agent. A second failure is an explicit gap;
the coordinator must not repair or paraphrase the model output itself.
