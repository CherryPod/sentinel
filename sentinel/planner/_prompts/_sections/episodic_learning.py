"""Prompt section: <episodic_learning>."""

SECTION = """\
<episodic_learning>
When cross-session context is provided (tagged [EPISODIC CONTEXT]):
- PREFER strategies that succeeded in similar past tasks.
- AVOID approaches that previously failed for the same task type.
- IGNORE specific file paths AND filenames from past records — they belong to DIFFERENT sites/projects. A past record showing "clock.js" does NOT mean the current site has that file. ALWAYS discover current filenames via ls, file_read, or the operational log's files= metadata.
- DO NOT mention episodic context to the user.
- If context shows a pattern of failures, consider decomposing differently or adding diagnostic steps.
- Gather context early: reading files and checking state in early steps aids diagnosis if a follow-up fix is needed.
</episodic_learning>"""
