use super::service::{self, Kind, text};
use crate::error::{AppError, AppResult};
use crate::hoops::authz::Principal;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};

fn payload(entry: &Value) -> AppResult<Value> {
    let data: Value = serde_json::from_str(text(entry, "message"))
        .map_err(|_| AppError::Validation("Entry message is not OpenClaw JSON".into()))?;
    if ["sessionId", "entryId", "kind"]
        .iter()
        .any(|key| text(&data, key).trim().is_empty())
    {
        return Err(AppError::Validation(
            "OpenClaw sessionId, entryId and kind are required".into(),
        ));
    }
    Ok(data)
}
pub fn build(anchor: &Value, entries: &[Value]) -> AppResult<Value> {
    let anchor_payload = payload(anchor)?;
    let session = text(&anchor_payload, "sessionId");
    let mut nodes = BTreeMap::<String, Value>::new();
    let mut calls = BTreeMap::<String, String>::new();
    let mut records = Vec::new();
    for entry in entries {
        if text(entry, "owner") != text(anchor, "owner")
            || text(entry, "provider") != text(anchor, "provider")
            || text(entry, "type") != "session"
        {
            continue;
        }
        let Ok(data) = payload(entry) else { continue };
        if text(&data, "sessionId") == session {
            records.push((entry, data));
        }
    }
    records.sort_by_key(|(entry, data)| {
        format!("{}:{}", text(data, "timestamp"), text(entry, "name"))
    });
    for (entry, data) in &records {
        let kind = text(data, "kind");
        if !["task", "tool_call", "tool_result", "final"].contains(&kind) {
            continue;
        }
        let mut node = data.clone();
        let original_id = text(data, "entryId");
        let id = if kind == "tool_call" {
            let call_id = text(data, "toolCallId");
            let id = if call_id.is_empty() {
                format!("tool_call_row:{}", text(entry, "name"))
            } else {
                format!("tool_call:{call_id}")
            };
            if !call_id.is_empty() {
                calls.insert(call_id.to_string(), id.clone());
            }
            nodes.entry(original_id.to_string()).or_insert_with(||json!({"id":original_id,"entryId":original_id,"parentId":text(data,"parentId"),"kind":"assistant_step","timestamp":text(data,"timestamp"),"summary":text(data,"tool"),"text":text(data,"assistantText"),"isAnchor":false}));
            node["parentId"] = json!(original_id);
            id
        } else {
            original_id.to_string()
        };
        node["id"] = json!(id);
        node["isAnchor"] = json!(text(entry, "name") == text(anchor, "name"));
        if text(&node, "timestamp").is_empty() {
            node["timestamp"] = json!(text(entry, "createdTime"));
        }
        node.as_object_mut().unwrap().remove("sessionId");
        nodes.insert(id, node);
    }
    for node in nodes.values_mut() {
        if text(node, "kind") == "tool_result" {
            if let Some(parent) = calls.get(text(node, "toolCallId")) {
                node["originalParentId"] = json!(text(node, "parentId"));
                node["parentId"] = json!(parent);
            }
        }
    }
    let mut edges = BTreeSet::new();
    for (id, node) in &nodes {
        let parent = text(node, "parentId");
        if parent != id && nodes.contains_key(parent) {
            edges.insert((parent.to_string(), id.to_string()));
        }
    }
    let count = |kind: &str| {
        nodes
            .values()
            .filter(|node| text(node, "kind") == kind)
            .count()
    };
    let stats = json!({"totalNodes":nodes.len(),"taskCount":count("task"),"toolCallCount":count("tool_call"),"toolResultCount":count("tool_result"),"finalCount":count("final"),"failedCount":nodes.values().filter(|node|node["ok"]==false||!text(node,"error").is_empty()).count()});
    let mut nodes: Vec<Value> = nodes.into_values().collect();
    nodes.sort_by_key(|node| format!("{}:{}", text(node, "timestamp"), text(node, "id")));
    Ok(
        json!({"nodes":nodes,"edges":edges.into_iter().map(|(source,target)|json!({"source":source,"target":target})).collect::<Vec<_>>(),"stats":stats}),
    )
}
pub async fn graph(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
) -> AppResult<Value> {
    service::authorize(principal, owner)?;
    let anchor = service::get(pool, Kind::Entry, owner, name)
        .await?
        .ok_or_else(|| AppError::NotFound("Entry not found".into()))?;
    if text(&anchor, "type") != "session" {
        return Err(AppError::Validation("Entry is not a session".into()));
    }
    let entries:Vec<Value>=sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='entry' AND owner=$1 AND document->>'type'='session' AND COALESCE(document->>'provider','')=$2 ORDER BY created_at,name")
        .bind(owner).bind(text(&anchor,"provider")).fetch_all(pool).await?;
    build(&anchor, &entries)
}
