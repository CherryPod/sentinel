"""Prompt section: <tool_selection>."""

SECTION = """\
<tool_selection>
Choose the correct tool based on whether the target file already exists:

CREATE (file does not exist yet):
- file_write: For non-viewable files (scripts, configs, data, logs) at /workspace/.
- website create: For browser-viewable pages at /workspace/sites/. Supports multiple files in a single call.

MODIFY (file already exists):
- file_patch: For ALL modifications to existing files — HTML, CSS, JS, Python, configs, YAML, data, any file type. file_patch applies a targeted change at a specific anchor point without regenerating the rest of the file.

The distinction is simple: if the file exists, use file_patch. If it does not exist, use file_write or website create.

Why this matters: the worker has an 8192-token output cap. When you ask it to regenerate an entire file to make a small change, it truncates content, enters repetition loops, or silently drops sections. file_patch avoids this by having the worker generate only the new/changed fragment, then splicing it in deterministically.

file_patch workflow (applies to all file types):
  1. file_read the target file with replan_after=true. MANDATORY.
  2. After the replan, check whether an [ANCHOR MAP] was provided for this file.

     If an anchor map IS present:
     - Select the appropriate named anchor from the map.
     - Use the full anchor marker as the anchor string:
       HTML:    <!-- anchor: {name} -->
       Python:  # anchor: {name}
       JS:      // anchor: {name}
       CSS:     /* anchor: {name} */
       Shell:   # anchor: {name}
       YAML:    # anchor: {name}
     - Common patterns:
       - Add content inside a section: insert_after the full marker
       - Add content at end of section: insert_before the "-end" marker
       - Replace entire section: anchor="{name}...{name}-end" (bare names, not full markers — executor builds markers), operation="replace"
       - Add content after a section: insert_after the "-end" marker
     - Do NOT use css: selectors or text anchors when named anchors are available.
     - Do NOT invent anchor names — only use names from the [ANCHOR MAP].

     If NO anchor map is present: fall back to manual anchor selection.
     - HTML: use css:#element-id selectors.
     - Non-HTML: copy a unique string verbatim from file content.
     In both cases, do NOT delegate anchor identification to an llm_task step.

     file_patch operations:
     - replace: Replaces the ENTIRE matched element (including its wrapper tag). Use ONLY when the structural boundary itself needs to change.
     - replace_inner: Replaces the CONTENT INSIDE the matched element, preserving the element itself (tag, ID, classes, attributes). PREFERRED for CSS selector patches — always use replace_inner unless you specifically need to change the element's tag or attributes.
     - insert_after / insert_before: Insert content after/before the matched element.
     - delete: Remove the matched element.
     IMPORTANT: When updating content inside an HTML element, ALWAYS use replace_inner + CSS selector. Using replace with a CSS selector will destroy the element's ID and classes, breaking the page structure.

  3. llm_task to generate ONLY the new/replacement content fragment.
  4. file_patch with the anchor and $content_variable.

<example type="good" title="Using named anchors from anchor map">
Anchor map provides: head-styles, el-status-panel, el-status-panel-end

To add CSS:
  file_patch anchor="<!-- anchor: head-styles -->", operation="insert_after", content=$new_css

To replace a panel's content:
  file_patch anchor="el-status-panel...el-status-panel-end", operation="replace", content=$new_panel

To add a new panel after an existing one:
  file_patch anchor="<!-- anchor: el-status-panel-end -->", operation="insert_after", content=$new_panel
</example>

<example type="bad" title="Inventing anchor names not in the map">
anchor="<!-- anchor: main-content -->"
WRONG: "main-content" is not in the anchor map. Only use names that appear in the [ANCHOR MAP] provided during replan. Named anchors are placed by the system — you cannot guess them.
</example>

<example type="bad" title="Using text anchors when named anchors exist">
anchor="<div id="status-panel">"
WRONG: The anchor map provides el-status-panel. Use the named anchor.
</example>

<example type="fallback" title="No anchor map available">
When no [ANCHOR MAP] is provided, use manual workflow:
- HTML: css:#element-id selectors
- Non-HTML: copy a unique string verbatim from file content
This is expected for new files or files modified outside the pipeline.
</example>

Anchor selection (fallback — no anchor map):
- HTML: css:#element-id is the preferred anchor type.
- JS/TS: fn:functionName or class:ClassName to target by name. replace_inner on fn: replaces the function body while preserving the signature.
- CSS: sel:.selector to target a CSS rule by its selector. replace_inner replaces the declarations while preserving the selector and braces.
- Python: fn:function_name or class:ClassName to target by name. replace_inner replaces the body while preserving the def/class line and decorators.
- Rust: fn:function_name, class:StructName, or block:ImplTarget.
- Any file: copy a unique string verbatim from file content (text anchor).
- Structural anchors (fn:, class:, sel:) are preferred over text anchors when modifying function bodies or CSS rules — they survive formatting changes.
- Operations: insert_after, insert_before, replace, replace_inner, delete.

Multi-file changes (e.g. HTML + CSS + JS, or source + config):
- Read all affected files first, then patch each in dependency order.
- If any file_patch fails, do NOT continue — replan to assess partial state.
- Backups are created automatically; backup_path is in step outcome metadata.

CRITICAL — css: prefix on HTML files targets HTML ELEMENTS, not CSS rules:
css:body on an HTML file resolves to the <body> tag, NOT the body {} CSS rule inside a <style> tag. There is NO way to target CSS rules inside <style> tags via file_patch. If you need to modify CSS properties, target the separate .css file using sel:body or sel:.class-name. This is why CSS must always be in separate .css files (see Website CSS constraint below).
</tool_selection>"""
