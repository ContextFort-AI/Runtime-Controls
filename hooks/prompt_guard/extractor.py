"""
Attacker content extractor - extracts user-controllable content from tool responses.

This module identifies and extracts content that could be attacker-controlled
from various tool responses (Jira, Confluence, Web, etc.) for injection scanning.
"""


def extract_attacker_content(tool_name, tool_response):
    """
    Extract only attacker-controllable content from tool responses.

    Args:
        tool_name: Name of the tool that produced the response
        tool_response: The tool's response data

    Returns:
        String containing extracted attacker-controllable content
    """

    if tool_name == "WebFetch":
        # Entire response is external content
        return str(tool_response)

    if tool_name == "WebSearch":
        # Extract titles and content snippets
        parts = []
        if isinstance(tool_response, dict):
            for key in ["title", "snippet", "content", "description"]:
                if key in tool_response:
                    parts.append(str(tool_response[key]))
            if "results" in tool_response:
                for r in tool_response.get("results", []):
                    parts.extend([str(r.get("title", "")), str(r.get("snippet", ""))])
        # Also handle string responses
        if isinstance(tool_response, str):
            return tool_response
        return "\n".join(filter(None, parts)) if parts else str(tool_response)

    if tool_name == "mcp__atlassian__getJiraIssue":
        parts = []
        if isinstance(tool_response, dict):
            fields = tool_response.get("fields", {})
            if fields.get("summary"):
                parts.append(f"Summary: {fields['summary']}")
            if fields.get("description"):
                parts.append(f"Description: {fields['description']}")
            if fields.get("environment"):
                parts.append(f"Environment: {fields['environment']}")
            if fields.get("labels"):
                parts.append(f"Labels: {', '.join(fields['labels'])}")
            # Extract comments
            comments = fields.get("comment", {}).get("comments", [])
            for c in comments:
                body = c.get("body", "")
                if body:
                    parts.append(f"Comment: {body}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__searchJiraIssuesUsingJql":
        parts = []
        if isinstance(tool_response, dict):
            for issue in tool_response.get("issues", []):
                fields = issue.get("fields", {})
                if fields.get("summary"):
                    parts.append(f"Summary: {fields['summary']}")
                if fields.get("description"):
                    parts.append(f"Description: {fields['description']}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__getJiraIssueRemoteIssueLinks":
        parts = []
        if isinstance(tool_response, list):
            for link in tool_response:
                obj = link.get("object", {})
                if obj.get("title"):
                    parts.append(f"Link: {obj['title']}")
                if obj.get("summary"):
                    parts.append(f"Summary: {obj['summary']}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__getConfluencePage":
        parts = []
        if isinstance(tool_response, dict):
            if tool_response.get("title"):
                parts.append(f"Title: {tool_response['title']}")
            # Body can be in different formats
            body = tool_response.get("body", {})
            if isinstance(body, str):
                parts.append(f"Content: {body}")
            elif isinstance(body, dict):
                for fmt in ["storage", "view", "export_view", "styled_view", "atlas_doc_format"]:
                    if fmt in body and body[fmt].get("value"):
                        parts.append(f"Content: {body[fmt]['value']}")
                        break
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__searchConfluenceUsingCql":
        parts = []
        if isinstance(tool_response, dict):
            for result in tool_response.get("results", []):
                if result.get("title"):
                    parts.append(f"Title: {result['title']}")
                if result.get("excerpt"):
                    parts.append(f"Excerpt: {result['excerpt']}")
                # Content body if present
                body = result.get("body", {})
                if isinstance(body, dict):
                    for fmt in ["storage", "view"]:
                        if fmt in body and body[fmt].get("value"):
                            parts.append(f"Content: {body[fmt]['value']}")
                            break
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__getConfluenceSpaces":
        parts = []
        if isinstance(tool_response, dict):
            for space in tool_response.get("results", []):
                if space.get("name"):
                    parts.append(f"Space: {space['name']}")
                desc = space.get("description", {})
                if isinstance(desc, dict) and desc.get("plain", {}).get("value"):
                    parts.append(f"Description: {desc['plain']['value']}")
                elif isinstance(desc, str):
                    parts.append(f"Description: {desc}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__getPagesInConfluenceSpace":
        parts = []
        if isinstance(tool_response, dict):
            for page in tool_response.get("results", []):
                if page.get("title"):
                    parts.append(f"Page: {page['title']}")
        return "\n".join(parts) if parts else ""

    if tool_name in ["mcp__atlassian__getConfluencePageFooterComments",
                      "mcp__atlassian__getConfluencePageInlineComments"]:
        parts = []
        if isinstance(tool_response, dict):
            for comment in tool_response.get("results", []):
                body = comment.get("body", {})
                if isinstance(body, str):
                    parts.append(f"Comment: {body}")
                elif isinstance(body, dict):
                    for fmt in ["storage", "view", "atlas_doc_format"]:
                        if fmt in body and body[fmt].get("value"):
                            parts.append(f"Comment: {body[fmt]['value']}")
                            break
                # For inline comments, also get textSelection
                props = comment.get("properties", {})
                if props.get("textSelection"):
                    parts.append(f"Selection: {props['textSelection']}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__getConfluencePageDescendants":
        parts = []
        if isinstance(tool_response, dict):
            for page in tool_response.get("results", []):
                if page.get("title"):
                    parts.append(f"Page: {page['title']}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__search":
        parts = []
        if isinstance(tool_response, dict):
            for result in tool_response.get("results", []):
                if result.get("title"):
                    parts.append(f"Title: {result['title']}")
                if result.get("excerpt"):
                    parts.append(f"Excerpt: {result['excerpt']}")
                if result.get("content"):
                    parts.append(f"Content: {result['content']}")
        return "\n".join(parts) if parts else ""

    if tool_name == "mcp__atlassian__fetch":
        parts = []
        if isinstance(tool_response, dict):
            # Jira issue
            if "fields" in tool_response:
                fields = tool_response["fields"]
                if fields.get("summary"):
                    parts.append(f"Summary: {fields['summary']}")
                if fields.get("description"):
                    parts.append(f"Description: {fields['description']}")
            # Confluence page
            if tool_response.get("title"):
                parts.append(f"Title: {tool_response['title']}")
            body = tool_response.get("body", {})
            if isinstance(body, str):
                parts.append(f"Content: {body}")
            elif isinstance(body, dict):
                for fmt in ["storage", "view"]:
                    if fmt in body and body[fmt].get("value"):
                        parts.append(f"Content: {body[fmt]['value']}")
                        break
        return "\n".join(parts) if parts else ""

    # Fallback: return stringified response (shouldn't happen for watched tools)
    return str(tool_response)
