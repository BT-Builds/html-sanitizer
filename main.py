import re
import os
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(title="HTML Sanitizer API", version="1.0.0")
# === BT Builds Standard Middleware (auto-injected) ===
from fastapi.middleware.cors import CORSMiddleware as _BTCors
app.add_middleware(_BTCors, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], expose_headers=["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset"])

@app.middleware("http")
async def _bt_add_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "btbuilds"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


API_KEY=os.env...Y", "html-sanitizer-key-change-me")

ALLOWED_TAGS = [
    "a", "abbr", "article", "b", "blockquote", "br", "caption", "cite", "code",
    "col", "colgroup", "dd", "del", "details", "div", "dl", "dt", "em",
    "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
    "head", "header", "hr", "html", "i", "img", "ins", "kbd", "li", "main",
    "mark", "nav", "ol", "p", "pre", "q", "rp", "rt", "ruby", "s", "samp",
    "section", "small", "span", "strike", "strong", "sub", "summary", "sup",
    "table", "tbody", "td", "template", "tfoot", "th", "thead", "time", "title",
    "tr", "u", "ul", "wbr"
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "name", "target", "rel", "title"],
    "img": ["src", "alt", "title", "width", "height"],
    "*": ["class", "id", "style"]
}

DANGEROUS_PATTERNS = [
    (r'\s*on\w+\s*=\s*["\'][^"\']*["\']', ''),
    (r'javascript:', ''),
    (r'data:text/html', ''),
    (r'vbscript:', ''),
    (r'expression\s*\(', ''),
]

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key is None or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

class SanitizeRequest(BaseModel):
    html: str
    allowed_tags: Optional[List[str]] = None
    allowed_attributes: Optional[dict] = None

class SanitizeResponse(BaseModel):
    sanitized_html: str
    removed_tags: List[str]
    removed_attributes: List[str]

def sanitize_html(html: str, custom_tags: Optional[List[str]] = None, custom_attrs: Optional[dict] = None) -> SanitizeResponse:
    tags = set(custom_tags) if custom_tags else set(ALLOWED_TAGS)
    attrs = custom_attrs if custom_attrs else ALLOWED_ATTRIBUTES

    removed_tags = []
    removed_attributes = []

    # Remove dangerous event handlers and protocols
    for pattern, replacement in DANGEROUS_PATTERNS:
        html = re.sub(pattern, replacement, html, flags=re.IGNORECASE)

    # Remove script and style tags with content
    html = re.sub(r'<\s*script[^>]*>.*?</\s*script\s*>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<\s*style[^>]*>.*?</\s*style\s*>', '', html, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML comments
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    # Find all tags and remove disallowed ones
    all_tags = list(re.finditer(r'<(/?)(\w+)[^>]*>', html, re.IGNORECASE))

    result = html
    for match in reversed(all_tags):
        full_match = match.group(0)
        tag_name = match.group(2).lower()

        if tag_name not in tags:
            removed_tags.append(tag_name)
            result = result[:match.start()] + result[match.end():]

    # Clean attributes on remaining tags
    def clean_attrs(match):
        tag_name = match.group(1).lower()
        tag_content = match.group(2)

        allowed_for_tag = attrs.get(tag_name, attrs.get('*', []))
        kept_attrs = []

        attr_matches = re.findall(r'(\w+)\s*=\s*["\']([^"\']*)["\']', tag_content)
        for attr_name, attr_value in attr_matches:
            attr_lower = attr_name.lower()
            if attr_lower in [a.lower() for a in allowed_for_tag]:
                kept_attrs.append(f'{attr_name}="{attr_value}"')
            else:
                removed_attributes.append(attr_name)

        if kept_attrs:
            return f"<{tag_name} {' '.join(kept_attrs)}>"
        return f"<{tag_name}>"

    result = re.sub(r'<(\w+)([^>]*)>', clean_attrs, result, flags=re.IGNORECASE)

    return SanitizeResponse(
        sanitized_html=result,
        removed_tags=list(set(removed_tags)),
        removed_attributes=list(set(removed_attributes))
    )

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/sanitize", dependencies=[Depends(verify_api_key)])
def sanitize(request: SanitizeRequest):
    if not request.html:
        raise HTTPException(status_code=400, detail="html field required")
    result = sanitize_html(request.html, request.allowed_tags, request.allowed_attributes)
    return result

@app.post("/strip-all", dependencies=[Depends(verify_api_key)])
def strip_all(request: SanitizeRequest):
    html = request.html
    html = re.sub(r'<\s*[^>]+>', '', html)
    html = re.sub(r'</\s*[^>]+>', '', html)
    html = re.sub(r'&lt;', '<', html)
    html = re.sub(r'&gt;', '>', html)
    html = re.sub(r'&amp;', '&', html)
    html = re.sub(r'&nbsp;', ' ', html)
    return {"sanitized_html": html.strip(), "removed_tags": [], "removed_attributes": []}

# Bulk endpoints
class BulkRequest(BaseModel):
    items: List[dict]

class BulkResultItem(BaseModel):
    input: Optional[str]
    output: Optional[dict]
    error: Optional[str]

class BulkResponse(BaseModel):
    results: List[BulkResultItem]
    total: int
    successful: int

@app.post("/bulk/sanitize", dependencies=[Depends(verify_api_key)])
def bulk_sanitize(request: BulkRequest):
    results = []
    successful = 0

    for item in request.items[:1000]:
        try:
            html = item.get("html", "")
            if not html:
                results.append(BulkResultItem(input=html, error="html field required"))
                continue
            allowed_tags = item.get("allowed_tags")
            allowed_attrs = item.get("allowed_attributes")
            result = sanitize_html(html, allowed_tags, allowed_attrs)
            results.append(BulkResultItem(input=html, output=result.model_dump()))
            successful += 1
        except Exception as e:
            results.append(BulkResultItem(input=item.get("html", ""), error=str(e)))

    return BulkResponse(results=results, total=len(results), successful=successful)

@app.post("/bulk/strip-all", dependencies=[Depends(verify_api_key)])
def bulk_strip_all(request: BulkRequest):
    results = []
    successful = 0

    for item in request.items[:1000]:
        try:
            html = item.get("html", "")
            if not html:
                results.append(BulkResultItem(input=html, error="html field required"))
                continue
            output = re.sub(r'<\s*[^>]+>', '', html)
            output = re.sub(r'</\s*[^>]+>', '', output)
            output = re.sub(r'&lt;', '<', output)
            output = re.sub(r'&gt;', '>', output)
            output = re.sub(r'&amp;', '&', output)
            output = re.sub(r'&nbsp;', ' ', output)
            output = output.strip()
            results.append(BulkResultItem(input=html, output={"sanitized_html": output, "removed_tags": [], "removed_attributes": []}))
            successful += 1
        except Exception as e:
            results.append(BulkResultItem(input=item.get("html", ""), error=str(e)))

    return BulkResponse(results=results, total=len(results), successful=successful)

try:
    from mangum import Mangum
    handler = Mangum(app, lifespan="off")
except ImportError:
    pass