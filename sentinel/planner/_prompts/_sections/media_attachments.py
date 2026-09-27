"""Prompt section: <media_attachments>."""

SECTION = """\
<media_attachments>
When a user request includes an [ATTACHMENTS] block, media files have been received and stored in the user's workspace. Each attachment is listed with its MIME type, size, and workspace path.

The attachment files already exist on disk — do NOT plan steps to download, fetch, or create them. Use the workspace paths directly.

To embed media in a website, use the "media" field on the website tool:
- "media": [{"source": "<workspace_path>", "dest": "<filename_in_site>"}]
- The "source" is the workspace path from the [ATTACHMENTS] block (verbatim).
- The "dest" is the filename the media will have inside the site directory.
- Reference the dest filename in your HTML (e.g. <video src="greeting.mp4">).
- Multiple media items can be included in one website call.

Media files are binary — they are NEVER passed through llm_task steps or included in worker prompts. Only the workspace path is referenced in tool args.

<example type="good" title="Signal video embedded in website">
User: "put this on a site for me"
[ATTACHMENTS]
- morning.mp4 (video/mp4, 5.0 MB): /workspace/1/media/inbox/abc-123/morning.mp4

{"plan_summary": "Create website with embedded video from Signal attachment",
 "steps": [
  {"id": "step_1", "type": "llm_task",
    "prompt": "Generate an HTML page that displays a video. The video file will be at 'morning.mp4' relative to the page. Use a <video> element with controls and autoplay muted attributes. Include a simple, clean layout. Link to style.css for styling. Do not add placeholder text or decorative elements beyond what is needed to present the video.",
    "output_var": "$html", "expects_code": true},
  {"id": "step_2", "type": "llm_task",
    "prompt": "Generate a CSS file for a video page. Style the body with a dark background, center the video horizontally and vertically. Set the video max-width to 90vw and max-height to 80vh. Use flexbox on body with flex-direction: column, justify-content: center, align-items: center.",
    "output_var": "$css", "expects_code": true},
  {"id": "step_3", "type": "tool_call", "tool": "website",
    "args": {"action": "create", "site_id": "morning-video",
      "files": {"index.html": "$html", "style.css": "$css"},
      "media": [{"source": "/workspace/1/media/inbox/abc-123/morning.mp4",
                  "dest": "morning.mp4"}]
    },
    "input_vars": ["$html", "$css"],
    "assertions": [
      {"assert": "file_exists", "path": "/workspace/1/sites/morning-video/index.html"},
      {"assert": "file_exists", "path": "/workspace/1/sites/morning-video/morning.mp4"},
      {"assert": "file_not_empty", "path": "/workspace/1/sites/morning-video/index.html"}
    ]
  }
]}
</example>

<example type="bad" title="Trying to read media with file_read">
WRONG: file_read on a video file is meaningless — it would return binary garbage. Media files are referenced by path in tool args, never read or processed through the text pipeline.
</example>

<example type="bad" title="Inventing a download step">
WRONG: {"type": "tool_call", "tool": "shell", "args": {"command": "curl ...attachment..."}}
Attachment files already exist at the workspace path listed in [ATTACHMENTS]. Do not plan download steps.
</example>
</media_attachments>"""
