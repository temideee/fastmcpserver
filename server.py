"""
FastMCP Server - Azure Resource Graph + ServiceNow Table API (FastMCP 2.14.0)
"""
from dotenv import load_dotenv
load_dotenv()

import os
from typing import Annotated, Optional, Literal, Any
from datetime import date, datetime, timedelta, timezone

from fastmcp import FastMCP, Context
from starlette.requests import Request
from starlette.responses import JSONResponse

import anyio
import httpx

from azure.identity import ClientSecretCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import QueryDefinition

from collections import defaultdict
import re

# ----------------------------
# MCP SERVER
# ----------------------------

def _require_api_key(ctx: Context) -> None:
    """
    Require callers to include x-api-key header matching MCP_API_KEY env var.
    """
    expected = os.environ.get("MCP_API_KEY")
    if not expected:
        raise PermissionError("Server misconfigured: MCP_API_KEY not set.")

    req = getattr(ctx, "request", None)
    if not req:
        raise PermissionError("Missing request context.")

    provided = req.headers.get("x-api-key")
    if not provided or provided != expected:
        raise PermissionError("Unauthorized: missing or invalid x-api-key.")

mcp = FastMCP(
    name="AzureServiceNowMCPServer",
    instructions="""
        FastMCP server deployed on Azure.
        Provides tools including:
        - Azure Resource Graph querying
        - Subscription summaries
        - Azure Cost queries
        - ServiceNow table tools (incident, request, kb, ppm tasks, sla)
    """,
    version="1.0.0",
)

# ----------------------------
# OPTIONAL AUTH (recommended for deployment)
# - If MCP_API_KEY is set, callers must send header: x-api-key: <value>
# - For local dev, omit MCP_API_KEY to disable auth.
# ----------------------------
def _require_api_key(ctx: Context) -> None:
    required = os.environ.get("MCP_API_KEY")
    if not required:
        return
    provided = None
    # Depending on client, ctx may expose request headers differently.
    # We'll try a few safe approaches.
    try:
        req = getattr(ctx, "request", None)
        if req and hasattr(req, "headers"):
            provided = req.headers.get("x-api-key")
    except Exception:
        provided = None
    if provided != required:
        raise PermissionError("Missing/invalid x-api-key")


_SCHEMA_CACHE = {}

KQL_DOCS_URL = "https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/refs/heads/main/articles/governance/resource-graph/concepts/query-language.md"
SCHEMA_DOCS_URL = "https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/refs/heads/main/articles/governance/resource-graph/reference/supported-tables-resources.md"

@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse(
        {"status": "healthy", "service": "fastmcp-server", "version": "1.0.0"}
    )

@mcp.tool(
    name="env_check",
    description="Check that required Azure and ServiceNow environment variables are present (does not print secrets)."
)
async def env_check(ctx: Context) -> dict[str, Any]:
    missing = []

    def need(name: str):
        if not os.environ.get(name):
            missing.append(name)

    # Azure
    need("AZURE_TENANT_ID")
    need("AZURE_CLIENT_ID")
    need("AZURE_CLIENT_SECRET")

    # ServiceNow
    need("SN_INSTANCE_URL")
    need("SN_USERNAME")
    need("SN_PASSWORD")

    return {
        "ok": len(missing) == 0,
        "missing": missing,
        "notes": "Secrets are not displayed. If missing, add to .env locally or App Settings in Azure."
    }

@mcp.resource("azure://kql/syntax")
async def get_kql_syntax() -> str:
    """
    Returns the official Azure Resource Graph KQL syntax documentation.
    Use this to understand supported KQL operators and language limitations.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(KQL_DOCS_URL)
        return response.text

@mcp.resource("azure://schema/tables")
async def get_arg_schema() -> str:
    """
    Returns the complete list of supported Azure Resource Graph tables and resource types.
    Use this to find the correct table names (e.g. Resources, ResourceContainers) and properties.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(SCHEMA_DOCS_URL)
        return response.text

async def _get_parsed_schema():
    """
    Downloads the schema markdown and parses it into a dict:
    { 'computeresources': ['microsoft.compute/virtualmachines', ...], ... }
    """
    if _SCHEMA_CACHE:
        return _SCHEMA_CACHE

    async with httpx.AsyncClient() as client:
        response = await client.get(SCHEMA_DOCS_URL)
        text = response.text

    sections = re.split(r'^##\s+', text, flags=re.MULTILINE)
    parsed_data = {}

    for section in sections[1:]:
        lines = section.strip().split('\n')
        table_name = lines[0].strip().lower()

        resources = []
        for line in lines[1:]:
            line = line.strip()
            if line.startswith('- ') and 'Sample query' not in line:
                clean_res = line.replace('- ', '').strip()
                clean_res = clean_res.replace('"', '')
                resources.append(clean_res)

        if resources:
            parsed_data[table_name] = resources

    _SCHEMA_CACHE.update(parsed_data)
    return parsed_data

@mcp.tool
async def search_azure_resource_schema(
    search_term: str,
    ctx: Context
) -> str:
    """
    Search for Azure Resource Graph table names and resource types.
    """
    _require_api_key(ctx)
    await ctx.info(f"Searching schema for: {search_term}")
    schema = await _get_parsed_schema()
    search_term = search_term.lower()

    matches = []
    for table, resources in schema.items():
        if search_term in table or any(search_term in r for r in resources):
            match_str = f"Table: {table}\nResources:\n" + "\n".join([f"  - {r}" for r in resources])
            matches.append(match_str)

    if not matches:
        return f"No tables found matching '{search_term}'. Try a broader term like 'resources' or 'security'."

    result_text = "\n\n".join(matches[:10])
    if len(matches) > 10:
        result_text += f"\n\n... (and {len(matches) - 10} more tables. Be more specific.)"

    return result_text

@mcp.tool
async def get_kql_syntax_guide(ctx: Context) -> str:
    """
    Returns the Azure Resource Graph KQL syntax docs (raw markdown).
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(KQL_DOCS_URL)
        return response.text

def _sp_credential_from_env() -> ClientSecretCredential:
    """Strict Service Principal auth only."""
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    missing = [k for k, v in {
        "AZURE_TENANT_ID": tenant_id,
        "AZURE_CLIENT_ID": client_id,
        "AZURE_CLIENT_SECRET": client_secret,
    }.items() if not v]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

def _build_kql(
    mode: str,
    resource_id: Optional[str],
    query: Optional[str],
    resource_type: Optional[str],
    limit: int,
) -> str:
    if mode == "by_id":
        if not resource_id:
            raise ValueError("resource_id is required when mode='by_id'")
        rid = resource_id.replace("'", "\\'")
        kql = (
            "resources "
            f"| where id =~ '{rid}' "
            "| project id, name, type, location, resourceGroup, subscriptionId, tags"
        )
    elif mode == "custom":
        if not query:
            raise ValueError("query is required when mode='custom'")
        kql = query
    else:
        kql = "resources | project id, name, type, location, resourceGroup, subscriptionId, tags"

    if resource_type:
        rt = resource_type.replace("'", "\\'").lower()
        kql = f"{kql} | where tolower(type) == '{rt}'"

    return f"{kql} | limit {int(limit)}"

@mcp.tool
async def fetch_azure_resources(
    subscriptions: Annotated[list[str], "Subscription IDs to query (one or many)"],
    ctx: Context,
    mode: Annotated[Literal["inventory", "by_id", "custom"], "Query mode"] = "inventory",
    resource_id: Annotated[Optional[str], "ARM resource ID (required for mode='by_id')"] = None,
    query: Annotated[Optional[str], "Resource Graph KQL (required for mode='custom')"] = None,
    resource_type: Annotated[Optional[str], "Filter type, e.g. microsoft.compute/virtualmachines"] = None,
    limit: Annotated[int, "Max rows to return"] = 200,
    skip_token: Annotated[Optional[str], "Paging token from prior call"] = None,
) -> dict[str, Any]:
    """Query Azure Resource Graph across one or more subscriptions using Service Principal auth."""
    _require_api_key(ctx)

    await ctx.info("Authenticating to Azure using Service Principal")
    await ctx.report_progress(progress=10, total=100)

    cred = _sp_credential_from_env()
    client = ResourceGraphClient(cred)

    kql = _build_kql(mode, resource_id, query, resource_type, limit)

    await ctx.info("Querying Azure Resource Graph")
    await ctx.report_progress(progress=60, total=100)

    req = QueryRequest(
        subscriptions=subscriptions,
        query=kql,
        options={
            "resultFormat": "objectArray",
            **({"skipToken": skip_token} if skip_token else {}),
        },
    )

    resp = await anyio.to_thread.run_sync(client.resources, req)

    await ctx.report_progress(progress=100, total=100)

    return {
        "mode": mode,
        "subscriptions": subscriptions,
        "query_executed": kql,
        "count": getattr(resp, "count", None),
        "total_records": getattr(resp, "total_records", None),
        "skip_token": getattr(resp, "skip_token", None),
        "data": getattr(resp, "data", None),
    }

def _friendly_category(resource_type: str) -> str:
    t = (resource_type or "").lower()
    if t == "microsoft.compute/virtualmachines":
        return "Virtual Machines"
    if t.startswith("microsoft.compute/"):
        return "Compute (other)"
    if t.startswith("microsoft.sql/") or t.startswith("microsoft.dbfor") or t.startswith("microsoft.documentdb/"):
        return "Databases"
    if t.startswith("microsoft.storage/"):
        return "Storage"
    if t.startswith("microsoft.network/"):
        return "Networking"
    if t.startswith("microsoft.web/"):
        return "App Service"
    if t.startswith("microsoft.containerservice/") or t.startswith("microsoft.containerregistry/"):
        return "Containers"
    if t.startswith("microsoft.keyvault/"):
        return "Key Vault"
    return "Other"

@mcp.tool
async def describe_subscription(
    subscription_id: Annotated[str, "Azure subscription ID"],
    ctx: Context,
    top_types: Annotated[int, "How many top resource types to return"] = 25,
) -> dict[str, Any]:
    """Return high-level subscription details and a rollup of resources inside it."""
    _require_api_key(ctx)

    await ctx.info(f"Loading subscription details for {subscription_id}")
    await ctx.report_progress(progress=10, total=100)

    cred = _sp_credential_from_env()

    sub_client = SubscriptionClient(cred)
    sub = await anyio.to_thread.run_sync(sub_client.subscriptions.get, subscription_id)

    await ctx.report_progress(progress=40, total=100)

    rg_client = ResourceGraphClient(cred)
    kql = """
resources
| summarize count() by type
| order by count_ desc
"""
    req = QueryRequest(
        subscriptions=[subscription_id],
        query=kql,
        options={"resultFormat": "objectArray"},
    )

    resp = await anyio.to_thread.run_sync(rg_client.resources, req)
    rows = getattr(resp, "data", []) or []

    await ctx.report_progress(progress=75, total=100)

    by_type = []
    category_counts: dict[str, int] = defaultdict(int)
    total_resources = 0

    for r in rows:
        r_type = r.get("type")
        c = int(r.get("count_", 0))
        total_resources += c
        category_counts[_friendly_category(r_type)] += c
        by_type.append({"type": r_type, "count": c})

    by_type = by_type[: max(1, int(top_types))]

    by_category = sorted(
        ({"category": k, "count": v} for k, v in category_counts.items()),
        key=lambda x: x["count"],
        reverse=True,
    )

    await ctx.report_progress(progress=100, total=100)

    return {
        "subscription": {
            "id": getattr(sub, "subscription_id", None) or getattr(sub, "subscriptionId", None) or subscription_id,
            "display_name": getattr(sub, "display_name", None) or getattr(sub, "displayName", None),
            "state": getattr(sub, "state", None),
            "tenant_id": getattr(sub, "tenant_id", None) or getattr(sub, "tenantId", None),
        },
        "resource_rollup": {
            "total_resources": total_resources,
            "by_category": by_category,
            "top_resource_types": by_type,
        },
        "notes": "Use fetch_azure_resources to drill into any type/category as needed.",
    }

def _utc_iso_z(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

def _default_range(period: str) -> tuple[date, date]:
    today = date.today()
    if period == "last_7_days":
        return today - timedelta(days=7), today
    if period == "last_30_days":
        return today - timedelta(days=30), today
    if period == "month_to_date":
        return today.replace(day=1), today
    return today - timedelta(days=30), today

@mcp.tool
async def fetch_costs(
    scope: Annotated[str, "Cost scope, e.g. /subscriptions/<subId>"],
    ctx: Context,
    granularity: Annotated[Literal["None", "Daily", "Monthly"], "Time granularity"] = "Daily",
    period: Annotated[Literal["last_7_days", "last_30_days", "month_to_date", "custom"], "Time period"] = "month_to_date",
    start_date: Annotated[Optional[str], "YYYY-MM-DD (required if period=custom)"] = None,
    end_date: Annotated[Optional[str], "YYYY-MM-DD (required if period=custom)"] = None,
    group_by: Annotated[Literal["none", "resource", "resource_group", "service_name"], "How to group costs"] = "none",
    resource_id: Annotated[Optional[str], "Optional ARM resource id to filter (exact match)"] = None,
    top: Annotated[int, "Top N groups by cost (only when grouped)"] = 25,
    metric: Annotated[Literal["Cost", "PreTaxCost"], "Cost metric to sum"] = "Cost",
) -> dict[str, Any]:
    """Fetch Azure cost data for a subscription (or narrower scope), optionally grouped or filtered by resource."""
    _require_api_key(ctx)

    await ctx.info("Querying Azure Cost Management")
    await ctx.report_progress(progress=10, total=100)

    cred = _sp_credential_from_env()
    client = CostManagementClient(cred)

    if period == "custom":
        if not start_date or not end_date:
            raise ValueError("start_date and end_date are required when period='custom'")
        start_d = date.fromisoformat(start_date)
        end_d = date.fromisoformat(end_date)
    else:
        start_d, end_d = _default_range(period)

    start_dt = datetime(start_d.year, start_d.month, start_d.day, tzinfo=timezone.utc)
    end_dt_excl = datetime(end_d.year, end_d.month, end_d.day, tzinfo=timezone.utc) + timedelta(days=1)

    grouping = []
    if group_by == "resource":
        grouping = [{"type": "Dimension", "name": "ResourceId"}]
    elif group_by == "resource_group":
        grouping = [{"type": "Dimension", "name": "ResourceGroupName"}]
    elif group_by == "service_name":
        grouping = [{"type": "Dimension", "name": "ServiceName"}]

    filter_clause = None
    if resource_id:
        filter_clause = {
            "dimensions": {
                "name": "ResourceId",
                "operator": "In",
                "values": [resource_id],
            }
        }

    q = QueryDefinition(
        type="Usage",
        timeframe="Custom",
        time_period={"from": _utc_iso_z(start_dt), "to": _utc_iso_z(end_dt_excl)},
        dataset={
            "granularity": granularity,
            "aggregation": {"totalCost": {"name": metric, "function": "Sum"}},
            **({"grouping": grouping} if grouping else {}),
            **({"filter": filter_clause} if filter_clause else {}),
        },
    )

    await ctx.report_progress(progress=60, total=100)
    result = await anyio.to_thread.run_sync(client.query.usage, scope, q)
    await ctx.report_progress(progress=90, total=100)

    d = result.as_dict() if hasattr(result, "as_dict") else {}
    columns = d.get("columns", []) or []
    rows = d.get("rows", []) or []

    if grouping and rows:
        cost_idx = 0
        for i, c in enumerate(columns):
            if (c.get("name") if isinstance(c, dict) else None) == "totalCost":
                cost_idx = i
                break
        rows = sorted(rows, key=lambda r: (r[cost_idx] or 0), reverse=True)[: max(1, int(top))]

    await ctx.report_progress(progress=100, total=100)

    return {
        "scope": scope,
        "timePeriod": {"from": _utc_iso_z(start_dt), "to": _utc_iso_z(end_dt_excl)},
        "granularity": granularity,
        "metric": metric,
        "group_by": group_by,
        "resource_id_filter": resource_id,
        "columns": columns,
        "rows": rows,
    }

@mcp.tool
async def get_server_info(ctx: Context) -> dict:
    """Return basic server/environment information."""
    _require_api_key(ctx)
    return {
        "server_name": "AzureServiceNowMCPServer",
        "version": "1.0.0",
        "environment": os.environ.get("ENVIRONMENT", "production"),
        "python_version": os.sys.version.split()[0],
    }

# ----------------------------
# SERVICENOW TOOLS (ADDED)
# ----------------------------

def _sn_base() -> str:
    base = os.environ.get("SN_INSTANCE_URL", "").rstrip("/")
    if not base.startswith("https://"):
        raise ValueError("SN_INSTANCE_URL must start with https://")
    return base

def _sn_basic_auth() -> Optional[tuple[str, str]]:
    u = os.environ.get("SN_USERNAME")
    p = os.environ.get("SN_PASSWORD")
    if u and p:
        return (u, p)
    return None

async def _sn_get_table(table: str, params: dict[str, Any]) -> dict[str, Any]:
    url = f"{_sn_base()}/api/now/table/{table}"
    auth = _sn_basic_auth()
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(url, headers=headers, params=params, auth=auth)
        r.raise_for_status()
        return r.json()

@mcp.tool(
    name="sn_table_query",
    description="Generic read-only ServiceNow Table API query tool. Use to query any table with an encoded sysparm_query, optionally limiting fields and result count."
)
async def sn_table_query(
    table: Annotated[str, "ServiceNow table name (e.g. incident, sc_request, kb_knowledge)"],
    ctx: Context,
    query: Annotated[str, "Encoded ServiceNow query (sysparm_query)"],
    limit: Annotated[int, "Maximum number of records to return"] = 10,
    fields: Annotated[Optional[str], "Comma-separated list of fields to return (optional)"] = None,
) -> dict[str, Any]:
    """
    Generic ServiceNow Table API query tool (read-only).

    Example:
      table="incident"
      query="active=true^ORDERBYDESCsys_created_on"
      limit=5
    """
    _require_api_key(ctx)

    params = {
        "sysparm_query": query,
        "sysparm_limit": str(limit),
        "sysparm_display_value": "true",
    }
    if fields:
        params["sysparm_fields"] = fields

    return await _sn_get_table(table, params)

@mcp.tool
async def sn_get_incident(
    number: Annotated[str, "Incident number e.g. INC0012345"],
    ctx: Context,
) -> dict[str, Any]:
    """
    Fetch a single ServiceNow Incident by its human-readable number (INC...).

    Use when a user asks for details of a specific incident, such as:
    status/state, short description, assignment group, assignee, priority, created/updated times.
    """
    _require_api_key(ctx)
    return await _sn_get_table("incident", {
        "sysparm_query": f"number={number}",
        "sysparm_limit": "1",
        "sysparm_display_value": "true",
    })


@mcp.tool
async def sn_search_incidents(
    query: Annotated[str, "Encoded query e.g. active=true^priority=1^ORDERBYDESCsys_created_on"],
    ctx: Context,
    limit: Annotated[int, "Max rows to return"] = 25,
) -> dict[str, Any]:
    """
    Search ServiceNow Incidents using a ServiceNow encoded query (sysparm_query).

    Use when a user asks for a list of incidents matching conditions, e.g.:
    - all P1 incidents
    - incidents assigned to a group
    - incidents created in the last 7 days

    The query must be ServiceNow encoded query format (caret-separated).
    """
    _require_api_key(ctx)
    return await _sn_get_table("incident", {
        "sysparm_query": query,
        "sysparm_limit": str(limit),
        "sysparm_display_value": "true",
    })


@mcp.tool
async def sn_get_request(
    number: Annotated[str, "Request number e.g. REQ0012345"],
    ctx: Context,
) -> dict[str, Any]:
    """
    Fetch a single ServiceNow Catalog Request (sc_request) by its number (REQ...).

    Use when a user asks for request details such as:
    requester, state, short description, opened/updated times, approvals.
    """
    _require_api_key(ctx)
    return await _sn_get_table("sc_request", {
        "sysparm_query": f"number={number}",
        "sysparm_limit": "1",
        "sysparm_display_value": "true",
    })


@mcp.tool
async def sn_get_kb_article(
    kb_number_or_sys_id: Annotated[str, "KB number (KB...) or sys_id"],
    ctx: Context,
) -> dict[str, Any]:
    """
    Fetch a ServiceNow Knowledge Base article (kb_knowledge) by KB number or sys_id.

    Use when a user asks for a specific KB article, its title, body text, or metadata.
    If the input isn't found as a KB number, this tool falls back to searching by sys_id.
    """
    _require_api_key(ctx)

    data = await _sn_get_table("kb_knowledge", {
        "sysparm_query": f"number={kb_number_or_sys_id}",
        "sysparm_limit": "1",
        "sysparm_display_value": "true",
    })
    if data.get("result"):
        return data

    return await _sn_get_table("kb_knowledge", {
        "sysparm_query": f"sys_id={kb_number_or_sys_id}",
        "sysparm_limit": "1",
        "sysparm_display_value": "true",
    })


@mcp.tool
async def sn_get_ppm_task(
    task_number: Annotated[str, "PPM task number (if your instance uses number), e.g. PTASK..."],
    ctx: Context,
) -> dict[str, Any]:
    """
    Fetch a ServiceNow Project/PPM task from pm_project_task by its number.

    Use when a user asks for PPM task details such as:
    state, assignment, planned dates, percent complete, and related project.

    Note: Some orgs use different tables/naming. If this returns 404 or empty,
    confirm your instance's correct PPM task table name.
    """
    _require_api_key(ctx)
    return await _sn_get_table("pm_project_task", {
        "sysparm_query": f"number={task_number}",
        "sysparm_limit": "1",
        "sysparm_display_value": "true",
    })


@mcp.tool
async def sn_get_sla_for_task(
    task_sys_id: Annotated[str, "sys_id of the task record (incident/request/etc.)"],
    ctx: Context,
    limit: Annotated[int, "Max rows to return"] = 50,
) -> dict[str, Any]:
    """
    Fetch SLA records (task_sla) related to a specific task sys_id.

    Use when a user asks:
    - what SLA is applied
    - breach status / time left
    - SLA history for an incident or request

    Input must be the task's sys_id (not the INC/REQ number).
    """
    _require_api_key(ctx)
    return await _sn_get_table("task_sla", {
        "sysparm_query": f"task={task_sys_id}",
        "sysparm_limit": str(limit),
        "sysparm_display_value": "true",
    })

@mcp.tool(
    name="sn_recent_incident_summaries",
    description="Return a clean list of recent incident summaries (number, short description, state, priority, assigned_to)."
)
async def sn_recent_incident_summaries(
    ctx: Context,
    limit: Annotated[int, "How many incidents"] = 10,
) -> dict[str, Any]:
    _require_api_key(ctx)
    data = await _sn_get_table("incident", {
        "sysparm_query": "sys_idISNOTEMPTY^ORDERBYDESCsys_created_on",
        "sysparm_limit": str(limit),
        "sysparm_display_value": "true",
        "sysparm_fields": "number,short_description,state,priority,assigned_to,assignment_group,sys_created_on"
    })
    results = data.get("result", []) or []
    clean = []
    for r in results:
        clean.append({
            "number": r.get("number"),
            "short_description": r.get("short_description"),
            "state": r.get("state"),
            "priority": r.get("priority"),
            "assigned_to": r.get("assigned_to"),
            "assignment_group": r.get("assignment_group"),
            "created": r.get("sys_created_on"),
        })
    return {"count": len(clean), "incidents": clean}

# ----------------------------
# RUN
# ----------------------------
if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    log_level = os.environ.get("LOG_LEVEL", "INFO")

    mcp.run(
        transport="http",
        host=host,
        port=port,
        log_level=log_level,
    )
