"""Prompt section: <output_schema>."""

SECTION = """\
<output_schema>
Respond ONLY with a JSON object (no markdown, no commentary):
{
  "plan_summary": "Brief description of what the plan does",
  "steps": [
    {
      "id": "step_1",
      "type": "llm_task",
      "description": "What this step does",
      "prompt": "The prompt to send to the LLM worker",
      "output_var": "$result_name",
      "expects_code": false,
      "input_vars": [],
      "output_format": null,
      "include_worker_history": false
    }
  ]
}

Step types:
- "llm_task": Send prompt to the text-processing LLM. Fields: prompt (required).
- "tool_call": Execute a tool action. Fields: tool (required), args (required). May include allowed_commands and allowed_paths (see PLAN-POLICY CONSTRAINTS).
Only "llm_task" and "tool_call" are valid step types.

Field reference:
- id: Unique per step (e.g. "step_1", "step_2").
- output_var: "$var_name" to store results. Reference in later steps via "$var_name".
- input_vars: $variables this step depends on. ONLY reference variables defined by a prior step's output_var. User "$" symbols (shell vars like $PATH, template strings like ${user}, dollar amounts) are NOT plan variables — include them verbatim and do NOT add to input_vars.
- expects_code: Set true when output may contain code, scripts, Containerfiles, configs with executable content, HTML with JavaScript, SQL, or shell commands. When in doubt, set true.
- output_format: null (freeform) | "json" (parseable JSON) | "tagged" (wrapped in <RESPONSE> tags). Only set when output feeds another step or tool.
- include_worker_history: boolean (optional, default false) — set true on llm_task steps where the worker benefits from seeing its prior output in this session (debugging, refinement, iteration). The controller injects truncated summaries of prior worker turns into the worker prompt.
- replan_after: boolean (optional, default false) — SET TRUE on discovery steps (ls, find, file_read) when later steps depend on the results (file names, directory structure, file contents). Without this, the plan ends after discovery and no actual work gets done. The controller executes up to this step, sends you the results, and asks you to continue with the correct paths/names. Maximum 3 per plan. Most fabrication-only plans need zero; discovery tasks almost always need one.

Post-condition assertions (REQUIRED for effect steps):
Every plan step that modifies files MUST include assertions verifying the change worked. Assertions are checked AFTER execution. Failed assertions trigger replanning with specific failure details — this is how the system self-corrects.
- "assertions": list of post-condition checks. Each assertion is a dict with an "assert" key naming the type, plus type-specific fields:
  - file_contains: {"assert": "file_contains", "path": "<file>", "pattern": "<regex>"} — verify the file contains the expected content after modification
  - file_not_contains: {"assert": "file_not_contains", "path": "<file>", "pattern": "<regex>"} — verify unwanted content was removed
  - file_exists: {"assert": "file_exists", "path": "<file>"} — verify file was created
  - file_not_empty: {"assert": "file_not_empty", "path": "<file>"} — verify file has content
  - content_changed: {"assert": "content_changed", "path": "<file>"} — verify file was actually modified
  - command_returns: {"assert": "command_returns", "cmd": "<command>", "exit_code": 0} — run a validation command (py_compile, node --check, json.tool) and check exit code
  - response_contains: {"assert": "response_contains", "step_id": "<id>", "pattern": "<regex>"} — verify tool output contains expected text
  - symbol_exists: {"assert": "symbol_exists", "path": "<file>", "symbol": "<name>"} — verify a structural element exists (HTML element ID, Python function/class, JS function, CSS selector). Uses parsed file data, more reliable than regex.
  - symbol_count: {"assert": "symbol_count", "path": "<file>", "class": "<classname>", "expected": N} — verify element count by CSS class. Or use "type": "function"/"class"/"selector" for Python/JS/CSS counts. Optional "op": "gte" (at least N) or "lte" (at most N).

Rules:
1. ALWAYS include content_changed for file_patch steps
2. For file_write: include file_exists + file_not_empty at minimum
3. For CSS changes: include file_contains with the expected property value regex
4. For JS files: include command_returns with "node --check <path>" when available
5. For Python files: include command_returns with "python3 -m py_compile <path>"
6. Add a "recovery" field describing what to do if the assertion fails
7. For tasks requesting multiple distinct elements (N panels, N functions, N sections), include at least one assertion per element verifying its presence in the output. Do not rely solely on file_exists/file_not_empty for multi-element tasks.
8. Prefer symbol_exists/symbol_count over file_contains for verifying structural elements — they use parsed file data and give better failure messages than regex matching.
9. symbol_exists "symbol" field: bare name for HTML (e.g., "btc-panel"), Python (e.g., "calculate"), JS (e.g., "updateClock"). For CSS, use the exact selector string (e.g., ".panel", "#btc-panel"). For Python constants/variables (not functions or classes), use file_contains instead — symbol_exists only checks function and class definitions.

Example — changing background to dark green:
{"assertions": [
  {"assert": "content_changed", "path": "/workspace/sites/glasgow/style.css",
    "recovery": "Re-read style.css and apply file_patch to correct selector"},
  {"assert": "file_contains", "path": "/workspace/sites/glasgow/style.css",
    "pattern": "background(-color)?:\\\\s*(darkgreen|#006400)",
    "recovery": "Verify the CSS selector targets the page background, not a component"}
]}

BAD example — creating a site with 4 panels (clock, date, bitcoin, weather):
{"assertions": [
  {"assert": "file_exists", "path": "/workspace/sites/dash/index.html"},
  {"assert": "file_not_empty", "path": "/workspace/sites/dash/index.html"},
  {"assert": "file_contains", "path": "/workspace/sites/dash/index.html", "pattern": "grid"}
]}
Problem: only checks file exists and contains "grid" somewhere. Missed verifying that 4 specific panels were created.

GOOD example — same task:
{"assertions": [
  {"assert": "symbol_count", "path": "/workspace/sites/dash/index.html",
   "class": "panel", "expected": 4,
   "recovery": "Ensure all panel divs have class='panel'"},
  {"assert": "symbol_exists", "path": "/workspace/sites/dash/index.html",
   "symbol": "btc-panel",
   "recovery": "Add btc-panel element to HTML"},
  {"assert": "symbol_exists", "path": "/workspace/sites/dash/index.html",
   "symbol": "weather-panel",
   "recovery": "Add weather-panel element to HTML"},
  {"assert": "command_returns",
   "cmd": "node --check /workspace/sites/dash/clock.js",
   "exit_code": 0}
]}
Each requested element has at least one assertion verifying its presence.
</output_schema>"""
