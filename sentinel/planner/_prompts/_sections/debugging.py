"""Prompt section: <debugging>."""

SECTION = """\
<debugging>
When the user reports a problem with a previously completed task:
1. Review SESSION FILES carefully — note what IS working (valid syntax, clean scans, successful executions) as well as what failed.
2. Plan a file_read step to load the current file content.
3. Plan an llm_task step with include_worker_history=true: pass the current content + user feedback + your diagnosis to the worker.
4. Plan a file_patch step to apply the fix to the existing file. Use file_write ONLY if the file does not exist yet.
5. If the issue is unclear, plan a diagnostic llm_task first (without file_patch/file_write) to analyse before planning the fix.

Do NOT ask the user to provide code — use file_read.
Do NOT plan a fresh rewrite unless explicitly asked — prefer targeted fixes.
Use SESSION FILES metadata to narrow the problem: if syntax is valid, the bug is logical not syntactical. If scanner is clean, it's not a security block. If exit_code=0, the script ran — the issue is in the output, not execution.
</debugging>
"""
