"""Prompt section: <constraints>."""

SECTION = """\
<constraints>
PLAN-POLICY CONSTRAINTS (tool_call steps involving shell_exec or file_write):

Include argument constraints defining the exact allowed scope:

- allowed_commands: BASE command names the step may execute. List only the command name (e.g. "find", "rm", "python3"), NOT full command strings with arguments.
  GOOD: ["find", "wc"]
  BAD:  ["find /workspace/ -type f -name '*.py' | wc -l"]  (full command lines rejected — metacharacters blocked)
  BAD:  ["rm -rf /workspace/build-cache/*"]  (arguments/globs in constraint — use allowed_paths for path scope)

- allowed_paths: File paths the step may access (within /workspace/, supports globs).
  GOOD: ["/workspace/build-cache/", "/workspace/dist/*.whl"]
  BAD:  ["/workspace/"]  (too broad — allows access anywhere in workspace)

<examples>
<example>
file_write step:
{"id": "step_1", "type": "tool_call", "tool": "file_write", "args": {"path": "/workspace/app.py", "content": "$app_code"}, "allowed_paths": ["/workspace/app.py"]}
</example>
<example>
shell_exec step:
{"id": "step_2", "type": "tool_call", "tool": "shell_exec", "args": {"command": "find /workspace/src -name '*.pyc' -delete"}, "allowed_commands": ["find"], "allowed_paths": ["/workspace/src/"]}
</example>
<example>
website step:
{"id": "step_3", "type": "tool_call", "tool": "website", "args": {"action": "create", "site_id": "green-page", "files": {"index.html": "$html_content"}, "title": "Green Page"}}
</example>
</examples>

Rules:
- Constraints MUST be as NARROW as possible — only what the step actually needs.
- Every shell_exec step MUST have allowed_commands.
- Every file_write and file_patch step MUST have allowed_paths.
- Paths outside /workspace/ are always rejected.
- The static denylist (reverse shells, pipe-to-shell, base64 exec, netcat, etc.) always blocks regardless of constraints.
- If constraints cannot be narrowly defined, leave fields as null — standard scanning with human approval applies.

All file paths must start with /workspace/. Do not plan access to secrets, credentials, or environment variables. Do not plan reverse shells, backdoors, or data exfiltration.
</constraints>"""
