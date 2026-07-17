#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::receipt::{body::ChioReceipt, decision::Decision};
use serde_json::{json, Value};

struct TestDir {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl std::ops::Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path.as_path()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.path.as_path()
    }
}

fn unique_test_dir() -> TestDir {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    TestDir {
        path: std::env::temp_dir().join(format!("chio-cli-mcp-serve-{nonce}")),
        _guard: guard,
    }
}

fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import os
import sys
import threading
import time

TOOLS = [
    {
        "name": "echo_json",
        "title": "Echo JSON",
        "description": "Return structured JSON",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "echo": {"type": "string"}
            },
            "required": ["echo"]
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "dangerous",
        "description": "A tool that should be hidden by policy",
        "inputSchema": {"type": "object"}
    },
    {
        "name": "sampled_echo",
        "description": "Uses sampling/createMessage before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sampled": {"type": "object"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "sampled_echo_tasked",
        "description": "Uses task-augmented sampling/createMessage before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sampled": {"type": "object"},
                "taskStatusBeforeResult": {"type": "string"},
                "taskStatusNotifications": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "sampled_echo_tasked_noisy",
        "description": "Uses task-augmented sampling/createMessage and emits notifications before tasks/get",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sampled": {"type": "object"},
                "taskStatusBeforeResult": {"type": "string"},
                "taskStatusNotifications": {"type": "integer"},
                "noiseCount": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "elicited_echo",
        "description": "Uses elicitation/create before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "elicited": {"type": "object"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "elicited_echo_tasked",
        "description": "Uses task-augmented elicitation/create before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "elicited": {"type": "object"},
                "taskStatusBeforeResult": {"type": "string"},
                "taskStatusNotifications": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "elicited_url_background",
        "description": "Uses URL-mode elicitation/create and later sends notifications/elicitation/complete",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "elicitationId": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "roots_echo",
        "description": "Uses roots/list before responding",
        "inputSchema": {"type": "object"},
        "outputSchema": {
            "type": "object",
            "properties": {
                "roots": {"type": "array"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "notify_resources",
        "description": "Emits resource update notifications before responding",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "notify_resources_background",
        "description": "Emits resource update notifications after the tool response",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "notify_catalog_changes_background",
        "description": "Emits tool and prompt catalog change notifications after the tool response",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "drop_stream_mid_call",
        "description": "Closes the MCP process before completing the tool response",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_echo",
        "description": "Sleeps briefly before responding",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    }
]

def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

FILESYSTEM_RESOURCES = os.environ.get("CHIO_TEST_FILESYSTEM_RESOURCES") == "1"

RESOURCES = [
    {
        "uri": "repo://docs/roadmap",
        "name": "Roadmap",
        "title": "Roadmap",
        "description": "Project roadmap",
        "mimeType": "text/markdown"
    }
]

if FILESYSTEM_RESOURCES:
    RESOURCES.extend([
        {
            "uri": "file:///workspace/project/docs/roadmap.md",
            "name": "Filesystem Roadmap",
            "title": "Filesystem Roadmap",
            "description": "In-root file-backed resource",
            "mimeType": "text/markdown"
        },
        {
            "uri": "file:///workspace/private/ops.md",
            "name": "Filesystem Ops",
            "title": "Filesystem Ops",
            "description": "Out-of-root file-backed resource",
            "mimeType": "text/plain"
        }
    ])

RESOURCE_TEMPLATES = [
    {
        "uriTemplate": "repo://docs/{slug}",
        "name": "Doc Template",
        "description": "Parameterized docs resource",
        "mimeType": "text/markdown"
    }
]

PROMPTS = [
    {
        "name": "summarize_docs",
        "title": "Summarize Docs",
        "description": "Summarize a documentation resource",
        "arguments": [
            {
                "name": "topic",
                "description": "Topic to summarize",
                "required": True
            }
        ]
    }
]

CLIENT_CAPABILITIES = {}

for raw in sys.stdin:
    line = raw.strip()
    if not line:
        continue

    message = json.loads(line)
    method = message.get("method")

    if method == "initialize":
        CLIENT_CAPABILITIES = message.get("params", {}).get("capabilities", {})
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": True, "listChanged": True},
                    "prompts": {"listChanged": True},
                    "completions": {}
                },
                "serverInfo": {"name": "mock-mcp", "version": "0.1.0"}
            }
        })
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"tools": TOOLS}
        })
        continue

    if method == "tools/call":
        params = message["params"]
        tool_name = params["name"]
        arguments = params.get("arguments", {})

        if tool_name == "sampled_echo":
            if "sampling" not in CLIENT_CAPABILITIES:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "sampling not negotiated"}],
                        "isError": True
                    }
                })
                continue

            sample_request_id = f"sample-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": sample_request_id,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "sample me")
                            }
                        }
                    ],
                    "maxTokens": 128
                }
            })

            while True:
                sample_response = json.loads(sys.stdin.readline())
                if sample_response.get("id") != sample_request_id or sample_response.get("method"):
                    continue
                if sample_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": sample_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                sampled = sample_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(sampled)}],
                        "structuredContent": {"sampled": sampled},
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "sampled_echo_tasked":
            task_caps = (
                CLIENT_CAPABILITIES.get("tasks", {})
                .get("requests", {})
                .get("sampling", {})
                .get("createMessage")
            )
            if "sampling" not in CLIENT_CAPABILITIES or task_caps is None:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "sampling task support not negotiated"}],
                        "isError": True
                    }
                })
                continue

            sample_request_id = f"sample-task-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": sample_request_id,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "sample me")
                            }
                        }
                    ],
                    "maxTokens": 128,
                    "task": {"ttl": 60000}
                }
            })

            sample_task_id = None
            status_notifications = 0
            while True:
                sample_response = json.loads(sys.stdin.readline())
                if sample_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if sample_response.get("id") != sample_request_id or sample_response.get("method"):
                    continue
                if sample_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": sample_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    sample_task_id = None
                    break

                sample_task_id = sample_response["result"]["task"]["taskId"]
                break

            if sample_task_id is None:
                continue

            time.sleep(0.15)

            task_get_request_id = f"task-get-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": task_get_request_id,
                "method": "tasks/get",
                "params": {"taskId": sample_task_id}
            })

            task_status = "unknown"
            while True:
                task_get_response = json.loads(sys.stdin.readline())
                if task_get_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if task_get_response.get("id") != task_get_request_id or task_get_response.get("method"):
                    continue
                if task_get_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": task_get_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    task_status = None
                    break
                task_status = task_get_response["result"]["status"]
                break

            if task_status is None:
                continue

            task_result_request_id = f"task-result-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": task_result_request_id,
                "method": "tasks/result",
                "params": {"taskId": sample_task_id}
            })

            while True:
                task_result_response = json.loads(sys.stdin.readline())
                if task_result_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if task_result_response.get("id") != task_result_request_id or task_result_response.get("method"):
                    continue
                if task_result_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": task_result_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                sampled = task_result_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(sampled)}],
                        "structuredContent": {
                            "sampled": sampled,
                            "taskStatusBeforeResult": task_status,
                            "taskStatusNotifications": status_notifications
                        },
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "sampled_echo_tasked_noisy":
            task_caps = (
                CLIENT_CAPABILITIES.get("tasks", {})
                .get("requests", {})
                .get("sampling", {})
                .get("createMessage")
            )
            if "sampling" not in CLIENT_CAPABILITIES or task_caps is None:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "sampling task support not negotiated"}],
                        "isError": True
                    }
                })
                continue

            sample_request_id = f"sample-task-noisy-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": sample_request_id,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "sample me")
                            }
                        }
                    ],
                    "maxTokens": 128,
                    "task": {"ttl": 60000}
                }
            })

            sample_task_id = None
            status_notifications = 0
            while True:
                sample_response = json.loads(sys.stdin.readline())
                if sample_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if sample_response.get("id") != sample_request_id or sample_response.get("method"):
                    continue
                if sample_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": sample_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    sample_task_id = None
                    break

                sample_task_id = sample_response["result"]["task"]["taskId"]
                break

            if sample_task_id is None:
                continue

            for idx in range(8):
                respond({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "debug",
                        "logger": "wrapped.noisy",
                        "data": {
                            "event": "sampling_task_noise",
                            "index": idx
                        }
                    }
                })

            task_get_request_id = f"task-get-noisy-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": task_get_request_id,
                "method": "tasks/get",
                "params": {"taskId": sample_task_id}
            })

            task_status = "unknown"
            while True:
                task_get_response = json.loads(sys.stdin.readline())
                if task_get_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if task_get_response.get("id") != task_get_request_id or task_get_response.get("method"):
                    continue
                if task_get_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": task_get_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    task_status = None
                    break
                task_status = task_get_response["result"]["status"]
                break

            if task_status is None:
                continue

            task_result_request_id = f"task-result-noisy-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": task_result_request_id,
                "method": "tasks/result",
                "params": {"taskId": sample_task_id}
            })

            while True:
                task_result_response = json.loads(sys.stdin.readline())
                if task_result_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if task_result_response.get("id") != task_result_request_id or task_result_response.get("method"):
                    continue
                if task_result_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": task_result_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                sampled = task_result_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(sampled)}],
                        "structuredContent": {
                            "sampled": sampled,
                            "taskStatusBeforeResult": task_status,
                            "taskStatusNotifications": status_notifications,
                            "noiseCount": 8
                        },
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "elicited_echo":
            if "elicitation" not in CLIENT_CAPABILITIES:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "elicitation not negotiated"}],
                        "isError": True
                    }
                })
                continue

            elicitation_request_id = f"elicit-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": elicitation_request_id,
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": arguments.get("message", "which environment should this target?"),
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "environment": {
                                "type": "string",
                                "enum": ["staging", "production"]
                            }
                        },
                        "required": ["environment"]
                    }
                }
            })

            while True:
                elicitation_response = json.loads(sys.stdin.readline())
                if elicitation_response.get("id") != elicitation_request_id or elicitation_response.get("method"):
                    continue
                if elicitation_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": elicitation_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                elicited = elicitation_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(elicited)}],
                        "structuredContent": {"elicited": elicited},
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "elicited_echo_tasked":
            task_caps = (
                CLIENT_CAPABILITIES.get("tasks", {})
                .get("requests", {})
                .get("elicitation", {})
                .get("create")
            )
            if "elicitation" not in CLIENT_CAPABILITIES or task_caps is None:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "elicitation task support not negotiated"}],
                        "isError": True
                    }
                })
                continue

            elicitation_request_id = f"elicit-task-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": elicitation_request_id,
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": arguments.get("message", "which environment should this target?"),
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "environment": {
                                "type": "string",
                                "enum": ["staging", "production"]
                            }
                        },
                        "required": ["environment"]
                    },
                    "task": {"ttl": 60000}
                }
            })

            elicitation_task_id = None
            status_notifications = 0
            while True:
                elicitation_response = json.loads(sys.stdin.readline())
                if elicitation_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if elicitation_response.get("id") != elicitation_request_id or elicitation_response.get("method"):
                    continue
                if elicitation_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": elicitation_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    elicitation_task_id = None
                    break

                elicitation_task_id = elicitation_response["result"]["task"]["taskId"]
                break

            if elicitation_task_id is None:
                continue

            time.sleep(0.15)

            task_get_request_id = f"elicit-task-get-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": task_get_request_id,
                "method": "tasks/get",
                "params": {"taskId": elicitation_task_id}
            })

            task_status = "unknown"
            while True:
                task_get_response = json.loads(sys.stdin.readline())
                if task_get_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if task_get_response.get("id") != task_get_request_id or task_get_response.get("method"):
                    continue
                if task_get_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": task_get_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    task_status = None
                    break
                task_status = task_get_response["result"]["status"]
                break

            if task_status is None:
                continue

            task_result_request_id = f"elicit-task-result-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": task_result_request_id,
                "method": "tasks/result",
                "params": {"taskId": elicitation_task_id}
            })

            while True:
                task_result_response = json.loads(sys.stdin.readline())
                if task_result_response.get("method") == "notifications/tasks/status":
                    status_notifications += 1
                    continue
                if task_result_response.get("id") != task_result_request_id or task_result_response.get("method"):
                    continue
                if task_result_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": task_result_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                elicited = task_result_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(elicited)}],
                        "structuredContent": {
                            "elicited": elicited,
                            "taskStatusBeforeResult": task_status,
                            "taskStatusNotifications": status_notifications
                        },
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "elicited_url_background":
            elicitation_caps = CLIENT_CAPABILITIES.get("elicitation", {})
            if elicitation_caps.get("url") is None:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "URL elicitation not negotiated"}],
                        "isError": True
                    }
                })
                continue

            elicitation_id = f"url-elicit-{message['id']}"
            elicitation_request_id = f"url-elicit-request-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": elicitation_request_id,
                "method": "elicitation/create",
                "params": {
                    "mode": "url",
                    "message": arguments.get("message", "complete the secure authorization flow"),
                    "url": f"https://example.test/authorize?elicitationId={elicitation_id}",
                    "elicitationId": elicitation_id
                }
            })

            while True:
                elicitation_response = json.loads(sys.stdin.readline())
                if elicitation_response.get("id") != elicitation_request_id or elicitation_response.get("method"):
                    continue
                if elicitation_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": elicitation_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                action = elicitation_response["result"]["action"]

                if action == "accept":
                    def emit_completion_notification():
                        time.sleep(0.10)
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/elicitation/complete",
                            "params": {
                                "elicitationId": elicitation_id
                            }
                        })

                    threading.Thread(target=emit_completion_notification, daemon=True).start()

                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"action": action, "elicitationId": elicitation_id})}],
                        "structuredContent": {
                            "action": action,
                            "elicitationId": elicitation_id
                        },
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "roots_echo":
            if "roots" not in CLIENT_CAPABILITIES:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "roots not negotiated"}],
                        "isError": True
                    }
                })
                continue

            roots_request_id = f"roots-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": roots_request_id,
                "method": "roots/list",
                "params": {}
            })

            while True:
                roots_response = json.loads(sys.stdin.readline())
                if roots_response.get("id") != roots_request_id or roots_response.get("method"):
                    continue
                if roots_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": roots_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                roots = roots_response["result"]["roots"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(roots)}],
                        "structuredContent": {"roots": roots},
                        "isError": False
                    }
                })
                break
            continue

        if tool_name == "echo_json":
            structured = {"echo": arguments.get("message", "")}
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": json.dumps(structured)}],
                    "structuredContent": structured,
                    "isError": False
                }
            })
            continue

        if tool_name == "notify_resources":
            respond({
                "jsonrpc": "2.0",
                "method": "notifications/resources/updated",
                "params": {
                    "uri": "repo://docs/roadmap"
                }
            })
            respond({
                "jsonrpc": "2.0",
                "method": "notifications/resources/updated",
                "params": {
                    "uri": "repo://secret/ops"
                }
            })
            respond({
                "jsonrpc": "2.0",
                "method": "notifications/resources/list_changed"
            })
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "resource notifications sent"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "notify_resources_background":
            def emit_notifications():
                time.sleep(0.10)
                respond({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {
                        "uri": "repo://docs/roadmap"
                    }
                })
                respond({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {
                        "uri": "repo://secret/ops"
                    }
                })
                respond({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/list_changed"
                })

            threading.Thread(target=emit_notifications, daemon=True).start()
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "background resource notifications scheduled"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "notify_catalog_changes_background":
            def emit_catalog_notifications():
                time.sleep(0.10)
                respond({
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed"
                })
                respond({
                    "jsonrpc": "2.0",
                    "method": "notifications/prompts/list_changed"
                })

            threading.Thread(target=emit_catalog_notifications, daemon=True).start()
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "catalog change notifications scheduled"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "drop_stream_mid_call":
            sys.stdout.flush()
            sys.exit(0)

        if tool_name == "slow_echo":
            time.sleep(0.25)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow response"}],
                    "isError": False
                }
            })
            continue

        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": "dangerous tool reached"}],
                "isError": False
            }
        })
        continue

    if method == "resources/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resources": RESOURCES}
        })
        continue

    if method == "resources/templates/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resourceTemplates": RESOURCE_TEMPLATES}
        })
        continue

    if method == "resources/read":
        uri = message["params"]["uri"]
        if uri == "file:///workspace/project/docs/roadmap.md":
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": "# Filesystem Roadmap"
                        }
                    ]
                }
            })
            continue
        if uri == "file:///workspace/private/ops.md":
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/plain",
                            "text": "ops"
                        }
                    ]
                }
            })
            continue
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/markdown",
                        "text": "# Roadmap"
                    }
                ]
            }
        })
        continue

    if method == "prompts/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"prompts": PROMPTS}
        })
        continue

    if method == "prompts/get":
        topic = message["params"].get("arguments", {}).get("topic", "docs")
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "description": "Summarize docs",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": f"Summarize {topic}"
                        }
                    }
                ]
            }
        })
        continue

    if method == "completion/complete":
        ref = message["params"]["ref"]
        argument = message["params"]["argument"]
        value = argument.get("value", "")

        if ref.get("type") == "ref/prompt" and ref.get("name") == "summarize_docs":
            values = [candidate for candidate in ["roadmap", "release-plan", "retro"] if candidate.startswith(value)]
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "completion": {
                        "values": values,
                        "total": len(values),
                        "hasMore": False
                    }
                }
            })
            continue

        if ref.get("type") == "ref/resource" and ref.get("uri") == "repo://docs/{slug}":
            values = [candidate for candidate in ["roadmap", "release-plan"] if candidate.startswith(value)]
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "completion": {
                        "values": values,
                        "total": len(values),
                        "hasMore": False
                    }
                }
            })
            continue

        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32602, "message": "completion target not found"}
        })
        continue

    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": f"unknown method: {method}"}
    })
"##;

    let path = dir.join("mock_mcp_server.py");
    fs::write(&path, script).expect("write mock MCP server");
    path
}

fn write_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
capabilities:
  default:
    tools:
      - server: wrapped-mock
        tool: echo_json
        operations: [invoke]
        ttl: 300
"#;

    let path = dir.join("policy.yaml");
    fs::write(&path, policy).expect("write policy");
    path
}

fn write_context_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
capabilities:
  default:
    tools:
      - server: wrapped-mock
        tool: echo_json
        operations: [invoke]
        ttl: 300
    resources:
      - uri: "repo://docs/*"
        operations: [read]
        ttl: 300
    prompts:
      - prompt: "summarize_*"
        operations: [get]
        ttl: 300
"#;

    let path = dir.join("context-policy.yaml");
    fs::write(&path, policy).expect("write context policy");
    path
}

fn write_resource_notification_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
capabilities:
  default:
    tools:
      - server: wrapped-mock
        tool: notify_resources
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: notify_resources_background
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: notify_catalog_changes_background
        operations: [invoke]
        ttl: 300
    resources:
      - uri: "repo://docs/*"
        operations: [read, subscribe]
        ttl: 300
"#;

    let path = dir.join("resource-notification-policy.yaml");
    fs::write(&path, policy).expect("write resource notification policy");
    path
}

fn write_filesystem_resource_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
capabilities:
  default:
    resources:
      - uri: "repo://docs/*"
        operations: [read]
        ttl: 300
      - uri: "file:///workspace/*"
        operations: [read]
        ttl: 300
"#;

    let path = dir.join("filesystem-resource-policy.yaml");
    fs::write(&path, policy).expect("write filesystem resource policy");
    path
}

fn write_incomplete_tool_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
capabilities:
  default:
    tools:
      - server: wrapped-mock
        tool: drop_stream_mid_call
        operations: [invoke]
        ttl: 300
"#;

    let path = dir.join("incomplete-tool-policy.yaml");
    fs::write(&path, policy).expect("write incomplete tool policy");
    path
}

fn write_nested_flow_policy(dir: &Path) -> PathBuf {
    let policy = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
  allow_sampling: true
  allow_elicitation: true
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
capabilities:
  default:
    tools:
      - server: wrapped-mock
        tool: sampled_echo
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: sampled_echo_tasked
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: sampled_echo_tasked_noisy
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: elicited_echo
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: elicited_echo_tasked
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: elicited_url_background
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: roots_echo
        operations: [invoke]
        ttl: 300
      - server: wrapped-mock
        tool: slow_echo
        operations: [invoke]
        ttl: 300
"#;

    let path = dir.join("nested-flow-policy.yaml");
    fs::write(&path, policy).expect("write nested flow policy");
    path
}

fn send_message(writer: &mut impl Write, value: &Value) {
    let line = serde_json::to_string(value).expect("serialize JSON-RPC request");
    writer.write_all(line.as_bytes()).expect("write request");
    writer.write_all(b"\n").expect("write newline");
    writer.flush().expect("flush request");
}

fn read_message(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read response");
    assert!(bytes > 0, "expected JSON-RPC response");
    serde_json::from_str(line.trim()).expect("parse JSON-RPC response")
}

fn read_response(reader: &mut impl BufRead, expected_id: u64) -> (Value, Vec<Value>) {
    let mut notifications = Vec::new();
    loop {
        let message = read_message(reader);
        if message.get("id").is_none() && message.get("method").is_some() {
            notifications.push(message);
            continue;
        }

        assert_eq!(message["id"], expected_id);
        return (message, notifications);
    }
}

fn read_response_with_nested_flow_support(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    expected_id: u64,
) -> (Value, Vec<Value>, Vec<Value>) {
    let mut notifications = Vec::new();
    let mut nested_requests = Vec::new();

    loop {
        let message = read_message(reader);
        if message.get("id").is_none() && message.get("method").is_some() {
            notifications.push(message);
            continue;
        }

        if message["method"] == "sampling/createMessage" {
            nested_requests.push(message.clone());
            send_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "role": "assistant",
                        "content": {
                            "type": "text",
                            "text": "sampled by client"
                        },
                        "model": "gpt-test",
                        "stopReason": "end_turn"
                    }
                }),
            );
            continue;
        }

        if message["method"] == "elicitation/create" {
            nested_requests.push(message.clone());
            let result = if message["params"]["mode"] == "url" {
                json!({
                    "action": "accept"
                })
            } else {
                json!({
                    "action": "accept",
                    "content": {
                        "environment": "staging"
                    }
                })
            };
            send_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": result
                }),
            );
            continue;
        }

        if message["method"] == "roots/list" {
            nested_requests.push(message.clone());
            send_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "roots": [
                            {
                                "uri": "file:///workspace/project",
                                "name": "Project"
                            }
                        ]
                    }
                }),
            );
            continue;
        }

        assert_eq!(message["id"], expected_id);
        return (message, notifications, nested_requests);
    }
}

fn read_response_with_nested_flow_cancellation(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    expected_id: u64,
) -> (Value, Vec<Value>, Vec<Value>) {
    let mut notifications = Vec::new();
    let mut nested_requests = Vec::new();

    loop {
        let message = read_message(reader);
        if message.get("id").is_none() && message.get("method").is_some() {
            notifications.push(message);
            continue;
        }

        if message["method"] == "sampling/createMessage" {
            nested_requests.push(message.clone());
            send_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": message["id"],
                        "reason": "user aborted sample"
                    }
                }),
            );
            continue;
        }

        assert_eq!(message["id"], expected_id);
        return (message, notifications, nested_requests);
    }
}

fn read_response_with_explicit_task_cancellation(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    expected_id: u64,
    cancel_id: u64,
    task_id: &str,
) -> (Value, Value, Vec<Value>, Vec<Value>) {
    let mut notifications = Vec::new();
    let mut nested_requests = Vec::new();
    let mut cancel_response = None;
    let mut task_result = None;

    loop {
        let message = read_message(reader);
        if message.get("id").is_none() && message.get("method").is_some() {
            notifications.push(message);
            continue;
        }

        if message["method"] == "sampling/createMessage" {
            nested_requests.push(message);
            send_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": cancel_id,
                    "method": "tasks/cancel",
                    "params": {
                        "taskId": task_id,
                    }
                }),
            );
            continue;
        }

        if message["id"] == cancel_id {
            cancel_response = Some(message);
        } else if message["id"] == expected_id {
            task_result = Some(message);
        } else {
            assert_eq!(message["id"], expected_id);
        }

        if task_result.is_some() && cancel_response.is_some() {
            return (
                task_result.take().expect("task result present"),
                cancel_response.take().expect("cancel response present"),
                notifications,
                nested_requests,
            );
        }
    }
}

fn read_response_with_parent_cancellation(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    expected_id: u64,
) -> (Value, Vec<Value>, Vec<Value>) {
    let mut notifications = Vec::new();
    let mut nested_requests = Vec::new();

    loop {
        let message = read_message(reader);
        if message.get("id").is_none() && message.get("method").is_some() {
            notifications.push(message);
            continue;
        }

        if message["method"] == "sampling/createMessage" {
            nested_requests.push(message.clone());
            send_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": expected_id,
                        "reason": "user aborted tool"
                    }
                }),
            );
            continue;
        }

        assert_eq!(message["id"], expected_id);
        return (message, notifications, nested_requests);
    }
}

fn read_messages_with_timeout(
    mut reader: BufReader<std::process::ChildStdout>,
    expected_count: usize,
    timeout: Duration,
) -> Vec<Value> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut messages = Vec::new();
        for _ in 0..expected_count {
            messages.push(read_message(&mut reader));
        }
        let _ = tx.send(messages);
    });

    rx.recv_timeout(timeout)
        .expect("timed out waiting for background notifications")
}

#[test]
fn mcp_serve_wraps_mcp_server_with_policy_filtered_edge() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(initialize["result"]["serverInfo"]["name"], "Chio MCP Edge");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    let (tools_list, tools_list_notifications) = read_response(&mut stdout, 2);
    assert!(tools_list_notifications.is_empty());
    let tools = tools_list["result"]["tools"]
        .as_array()
        .expect("tool array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "echo_json");
    assert_eq!(tools[0]["outputSchema"]["type"], "object");
    assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "hello edge"}
            }
        }),
    );
    let (allowed, allowed_notifications) = read_response(&mut stdout, 3);
    assert!(allowed_notifications.is_empty());
    assert_eq!(allowed["result"]["isError"], false);
    assert_eq!(allowed["result"]["structuredContent"]["echo"], "hello edge");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "dangerous",
                "arguments": {}
            }
        }),
    );
    let (denied, denied_notifications) = read_response(&mut stdout, 4);
    assert_eq!(denied["result"]["isError"], true);
    assert!(denied["result"]["content"][0]["text"]
        .as_str()
        .expect("denial text")
        .contains("not authorized"));
    assert_eq!(denied_notifications.len(), 1);
    assert_eq!(denied_notifications[0]["params"]["level"], "warning");

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_wraps_resources_prompts_and_completion() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_context_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["prompts"]["listChanged"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["completions"],
        json!({})
    );
    assert_eq!(initialize["result"]["capabilities"]["logging"], json!({}));

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }),
    );
    let (resources_list, resources_notifications) = read_response(&mut stdout, 2);
    assert!(resources_notifications.is_empty());
    let resources = resources_list["result"]["resources"]
        .as_array()
        .expect("resource array");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"], "repo://docs/roadmap");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/templates/list",
            "params": {}
        }),
    );
    let (templates_list, template_notifications) = read_response(&mut stdout, 3);
    assert!(template_notifications.is_empty());
    let templates = templates_list["result"]["resourceTemplates"]
        .as_array()
        .expect("resource template array");
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0]["uriTemplate"], "repo://docs/{slug}");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": { "uri": "repo://docs/roadmap" }
        }),
    );
    let (resource_read, resource_read_notifications) = read_response(&mut stdout, 4);
    assert!(resource_read_notifications.is_empty());
    assert_eq!(resource_read["result"]["contents"][0]["text"], "# Roadmap");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "prompts/list",
            "params": {}
        }),
    );
    let (prompts_list, prompt_notifications) = read_response(&mut stdout, 5);
    assert!(prompt_notifications.is_empty());
    let prompts = prompts_list["result"]["prompts"]
        .as_array()
        .expect("prompt array");
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0]["name"], "summarize_docs");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "prompts/get",
            "params": { "name": "summarize_docs", "arguments": { "topic": "roadmap" } }
        }),
    );
    let (prompt_get, prompt_get_notifications) = read_response(&mut stdout, 6);
    assert!(prompt_get_notifications.is_empty());
    assert_eq!(
        prompt_get["result"]["messages"][0]["content"]["text"],
        "Summarize roadmap"
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/prompt", "name": "summarize_docs" },
                "argument": { "name": "topic", "value": "re" },
                "context": { "arguments": {} }
            }
        }),
    );
    let (prompt_completion, prompt_completion_notifications) = read_response(&mut stdout, 7);
    assert!(prompt_completion_notifications.is_empty());
    assert_eq!(
        prompt_completion["result"]["completion"]["values"],
        json!(["release-plan", "retro"])
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "repo://docs/{slug}" },
                "argument": { "name": "slug", "value": "ro" },
                "context": { "arguments": {} }
            }
        }),
    );
    let (resource_completion, resource_completion_notifications) = read_response(&mut stdout, 8);
    assert!(resource_completion_notifications.is_empty());
    assert_eq!(
        resource_completion["result"]["completion"]["values"],
        json!(["roadmap"])
    );

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_enforces_filesystem_resource_roots_with_signed_evidence() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_filesystem_resource_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_TEST_FILESYSTEM_RESOURCES", "1")
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "roots": {"listChanged": true}
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    let bootstrap_roots = read_message(&mut stdout);
    assert_eq!(bootstrap_roots["method"], "roots/list");
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": bootstrap_roots["id"],
            "result": {
                "roots": [
                    {
                        "uri": "file:///workspace/project",
                        "name": "Project"
                    }
                ]
            }
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/project/docs/roadmap.md" }
        }),
    );
    let (allowed, _allowed_notifications) = read_response(&mut stdout, 2);
    assert_eq!(
        allowed["result"]["contents"][0]["text"],
        "# Filesystem Roadmap"
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/private/ops.md" }
        }),
    );
    let (denied, _denied_notifications) = read_response(&mut stdout, 3);
    assert_eq!(denied["error"]["code"], -32602);
    assert_eq!(
        denied["error"]["message"],
        "resource read denied: filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
    );
    let receipt: ChioReceipt = serde_json::from_value(denied["error"]["data"]["receipt"].clone())
        .expect("deserialize deny receipt");
    assert!(receipt
        .verify_signature()
        .expect("verify receipt signature"));
    assert!(receipt.is_denied());
    assert_eq!(receipt.tool_name, "resources/read");
    assert_eq!(receipt.tool_server, "session");
    match &receipt.decision {
        Some(Decision::Deny { reason, guard }) => {
            assert_eq!(guard, "session_roots");
            assert_eq!(
                reason,
                "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
            );
        }
        other => panic!("expected deny decision, got {other:?}"),
    }

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_denies_filesystem_resources_when_roots_are_missing() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_filesystem_resource_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_TEST_FILESYSTEM_RESOURCES", "1")
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/project/docs/roadmap.md" }
        }),
    );
    let (denied, _denied_notifications) = read_response(&mut stdout, 2);
    assert_eq!(denied["error"]["code"], -32602);
    assert_eq!(
        denied["error"]["message"],
        "resource read denied: no enforceable filesystem roots are available for this session"
    );
    let receipt: ChioReceipt = serde_json::from_value(denied["error"]["data"]["receipt"].clone())
        .expect("deserialize deny receipt");
    assert!(receipt
        .verify_signature()
        .expect("verify receipt signature"));
    assert!(receipt.is_denied());
    assert_eq!(receipt.tool_name, "resources/read");
    assert_eq!(receipt.tool_server, "session");
    match &receipt.decision {
        Some(Decision::Deny { reason, guard }) => {
            assert_eq!(guard, "session_roots");
            assert_eq!(
                reason,
                "no enforceable filesystem roots are available for this session"
            );
        }
        other => panic!("expected deny decision, got {other:?}"),
    }

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_propagates_wrapped_resource_notifications_for_subscribed_uris() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_resource_notification_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["listChanged"],
        true
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "repo://docs/roadmap" }
        }),
    );
    let (subscribe, subscribe_notifications) = read_response(&mut stdout, 2);
    assert!(subscribe_notifications.is_empty());
    assert_eq!(subscribe["result"], json!({}));
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "notify_resources",
                "arguments": {}
            }
        }),
    );
    let (tool_response, notifications) = read_response(&mut stdout, 3);
    assert_eq!(tool_response["result"]["isError"], false);

    let resource_updates = notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/resources/updated")
        .collect::<Vec<_>>();
    assert_eq!(resource_updates.len(), 1);
    assert_eq!(resource_updates[0]["params"]["uri"], "repo://docs/roadmap");
    assert!(notifications
        .iter()
        .any(|notification| { notification["method"] == "notifications/resources/list_changed" }));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_propagates_wrapped_background_resource_notifications_while_idle() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_resource_notification_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["listChanged"],
        true
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "repo://docs/roadmap" }
        }),
    );
    let (subscribe, subscribe_notifications) = read_response(&mut stdout, 2);
    assert!(subscribe_notifications.is_empty());
    assert_eq!(subscribe["result"], json!({}));

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "notify_resources_background",
                "arguments": {}
            }
        }),
    );
    let (tool_response, notifications_during_call) = read_response(&mut stdout, 3);
    assert_eq!(tool_response["result"]["isError"], false);
    let remaining_notifications = 2_usize
        .checked_sub(notifications_during_call.len())
        .expect("unexpected extra resource notifications during call");
    let mut background_notifications = notifications_during_call;
    background_notifications.extend(read_messages_with_timeout(
        stdout,
        remaining_notifications,
        Duration::from_secs(2),
    ));
    let resource_updates = background_notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/resources/updated")
        .collect::<Vec<_>>();
    assert_eq!(resource_updates.len(), 1);
    assert_eq!(resource_updates[0]["params"]["uri"], "repo://docs/roadmap");
    assert!(background_notifications
        .iter()
        .any(|notification| { notification["method"] == "notifications/resources/list_changed" }));
    drop(stdin);
    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");
    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_propagates_wrapped_catalog_change_notifications_while_idle() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_resource_notification_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(
        initialize["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["prompts"]["listChanged"],
        true
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "notify_catalog_changes_background",
                "arguments": {}
            }
        }),
    );
    let (tool_response, notifications_during_call) = read_response(&mut stdout, 2);
    assert_eq!(tool_response["result"]["isError"], false);
    let remaining_notifications = 2_usize
        .checked_sub(notifications_during_call.len())
        .expect("unexpected extra catalog notifications during call");
    let mut catalog_notifications = notifications_during_call;
    catalog_notifications.extend(read_messages_with_timeout(
        stdout,
        remaining_notifications,
        Duration::from_secs(2),
    ));
    assert!(catalog_notifications
        .iter()
        .any(|notification| notification["method"] == "notifications/tools/list_changed"));
    assert!(catalog_notifications
        .iter()
        .any(|notification| notification["method"] == "notifications/prompts/list_changed"));
    drop(stdin);
    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");
    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_returns_error_result_when_wrapped_stream_ends_mid_call() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_incomplete_tool_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "drop_stream_mid_call",
                "arguments": {}
            }
        }),
    );
    let (tool_response, notifications_during_call) = read_response(&mut stdout, 2);
    assert!(notifications_during_call.is_empty());
    assert_eq!(tool_response["result"]["isError"], true);
    let message = tool_response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text");
    assert!(message.contains("closed stdout"));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_proxies_wrapped_sampling_and_roots_requests() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);
    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "roots": {"listChanged": true},
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    let bootstrap_roots = read_message(&mut stdout);
    assert_eq!(bootstrap_roots["method"], "roots/list");
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": bootstrap_roots["id"],
            "result": {
                "roots": [
                    {
                        "uri": "file:///workspace/project",
                        "name": "Project"
                    }
                ]
            }
        }),
    );
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "sample this"},
                "_meta": {"progressToken": "progress-sampled"}
            }
        }),
    );
    let (sampled, sampled_notifications, sampled_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 2);
    assert!(!sampled_requests.is_empty());
    assert_eq!(sampled_requests[0]["method"], "sampling/createMessage");
    assert_eq!(sampled["result"]["isError"], false);
    assert_eq!(
        sampled["result"]["structuredContent"]["sampled"]["content"]["text"],
        "sampled by client"
    );
    let sampled_progress = sampled_notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/progress")
        .collect::<Vec<_>>();
    assert_eq!(sampled_progress.len(), 2);
    assert_eq!(
        sampled_progress[0]["params"]["progressToken"],
        "progress-sampled"
    );
    assert_eq!(sampled_progress[0]["params"]["progress"], 1);
    assert_eq!(
        sampled_progress[1]["params"]["progressToken"],
        "progress-sampled"
    );
    assert_eq!(sampled_progress[1]["params"]["progress"], 2);
    assert!(sampled_notifications.iter().any(|notification| {
        notification["params"]["data"]["event"] == "sampling_request_started"
    }));

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "roots_echo",
                "arguments": {}
            }
        }),
    );
    let (roots, roots_notifications, roots_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 3);
    assert!(!roots_requests.is_empty());
    assert_eq!(roots_requests[0]["method"], "roots/list");
    assert_eq!(
        roots["result"]["structuredContent"]["roots"][0]["uri"],
        "file:///workspace/project"
    );
    assert!(roots_notifications.iter().any(|notification| {
        notification["params"]["data"]["event"] == "roots_request_started"
    }));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_supports_task_augmented_wrapped_sampling_requests() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo_tasked",
                "arguments": {"message": "sample this through tasks"}
            }
        }),
    );
    let (sampled, sampled_notifications, sampled_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 2);
    assert_eq!(sampled_requests.len(), 1);
    assert_eq!(sampled_requests[0]["method"], "sampling/createMessage");
    assert_eq!(sampled["result"]["isError"], false);
    assert_eq!(
        sampled["result"]["structuredContent"]["taskStatusBeforeResult"],
        "completed"
    );
    assert!(
        sampled["result"]["structuredContent"]["taskStatusNotifications"]
            .as_u64()
            .expect("task status notification count")
            >= 1
    );
    assert_eq!(
        sampled["result"]["structuredContent"]["sampled"]["content"]["text"],
        "sampled by client"
    );
    assert!(sampled_notifications
        .iter()
        .all(|notification| notification["method"] != "notifications/tasks/status"));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_supports_task_augmented_wrapped_elicitation_requests() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "elicitation": {
                        "form": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "elicited_echo_tasked",
                "arguments": {"message": "confirm the deployment environment"}
            }
        }),
    );
    let (elicited, elicited_notifications, nested_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 2);
    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "elicitation/create");
    assert_eq!(nested_requests[0]["params"]["mode"], "form");
    assert_eq!(elicited["result"]["isError"], false);
    assert_eq!(
        elicited["result"]["structuredContent"]["taskStatusBeforeResult"],
        "completed"
    );
    assert!(
        elicited["result"]["structuredContent"]["taskStatusNotifications"]
            .as_u64()
            .expect("task status notification count")
            >= 1
    );
    assert_eq!(
        elicited["result"]["structuredContent"]["elicited"]["content"]["environment"],
        "staging"
    );
    assert_eq!(
        elicited["result"]["structuredContent"]["elicited"]["action"],
        "accept"
    );
    assert!(elicited_notifications
        .iter()
        .all(|notification| notification["method"] != "notifications/tasks/status"));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_forwards_wrapped_url_elicitation_completion_notifications() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "elicitation": {
                        "form": {},
                        "url": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "elicited_url_background",
                "arguments": {"message": "complete the secure authorization flow"}
            }
        }),
    );
    let (tool_response, tool_notifications, nested_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 2);
    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "elicitation/create");
    assert_eq!(nested_requests[0]["params"]["mode"], "url");
    assert_eq!(tool_response["result"]["isError"], false);
    assert_eq!(
        tool_response["result"]["structuredContent"]["action"],
        "accept"
    );
    let elicitation_id = tool_response["result"]["structuredContent"]["elicitationId"]
        .as_str()
        .expect("elicitation id")
        .to_string();
    let mut completion_notifications = tool_notifications
        .into_iter()
        .filter(|notification| notification["method"] == "notifications/elicitation/complete")
        .collect::<Vec<_>>();
    if completion_notifications.is_empty() {
        completion_notifications.extend(
            read_messages_with_timeout(stdout, 1, Duration::from_secs(2))
                .into_iter()
                .filter(|notification| {
                    notification["method"] == "notifications/elicitation/complete"
                }),
        );
    }
    assert_eq!(completion_notifications.len(), 1);
    assert_eq!(
        completion_notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(
        completion_notifications[0]["params"]["elicitationId"],
        elicitation_id
    );
    drop(stdin);
    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");
    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_propagates_nested_sampling_cancellation() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "sample this"},
                "_meta": {"progressToken": "progress-cancelled"}
            }
        }),
    );
    let (cancelled, cancelled_notifications, nested_requests) =
        read_response_with_nested_flow_cancellation(&mut stdout, &mut stdin, 2);
    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "sampling/createMessage");
    assert_eq!(cancelled["result"]["isError"], true);
    assert!(cancelled["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text")
        .contains("cancelled by client"));

    let progress = cancelled_notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/progress")
        .collect::<Vec<_>>();
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0]["params"]["progressToken"], "progress-cancelled");
    assert_eq!(progress[0]["params"]["progress"], 1);

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_propagates_parent_tool_cancellation_during_nested_sampling() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "sample this"},
                "_meta": {"progressToken": "progress-parent-cancelled"}
            }
        }),
    );
    let (cancelled, cancelled_notifications, nested_requests) =
        read_response_with_parent_cancellation(&mut stdout, &mut stdin, 2);
    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "sampling/createMessage");
    assert_eq!(cancelled["result"]["isError"], true);
    let cancelled_text = cancelled["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text");
    assert!(cancelled_text.contains("cancelled by client"));
    assert!(cancelled_text.contains("user aborted tool"));

    let progress = cancelled_notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/progress")
        .collect::<Vec<_>>();
    assert_eq!(progress.len(), 1);
    assert_eq!(
        progress[0]["params"]["progressToken"],
        "progress-parent-cancelled"
    );
    assert_eq!(progress[0]["params"]["progress"], 1);

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_propagates_parent_tool_cancellation_outside_nested_flow_windows() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": {}
            }
        }),
    );
    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": 2,
                "reason": "user aborted slow tool"
            }
        }),
    );

    let (cancelled, cancelled_notifications) = read_response(&mut stdout, 2);
    assert!(cancelled_notifications.is_empty());
    assert_eq!(cancelled["result"]["isError"], true);
    assert!(cancelled["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text")
        .contains("cancelled by client: user aborted slow tool"));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_completes_task_in_background_and_emits_status_notification() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": {},
                "task": {}
            }
        }),
    );
    let (create_task, create_notifications) = read_response(&mut stdout, 2);
    assert!(create_notifications.is_empty());
    assert_eq!(
        create_task["result"]["task"]["ownership"]["workOwner"],
        "task"
    );
    assert_eq!(
        create_task["result"]["task"]["ownership"]["resultStreamOwner"],
        "request_stream"
    );
    assert_eq!(
        create_task["result"]["task"]["ownership"]["statusNotificationOwner"],
        "session_notification_stream"
    );
    assert_eq!(
        create_task["result"]["task"]["ownership"]["terminalStateOwner"],
        "task"
    );
    assert!(create_task["result"]["task"]["ownerRequestId"]
        .as_str()
        .expect("owner request id")
        .starts_with("mcp-edge-req-"));
    assert!(create_task["result"]["task"]["parentRequestId"].is_null());
    let task_id = create_task["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();
    assert_eq!(create_task["result"]["task"]["status"], "working");

    std::thread::sleep(Duration::from_millis(400));

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    let (task_get, task_get_notifications) = read_response(&mut stdout, 3);
    assert_eq!(task_get["result"]["status"], "completed");
    assert_eq!(
        task_get["result"]["ownership"]["terminalStateOwner"],
        "task"
    );
    assert!(task_get_notifications.iter().any(|notification| {
        notification["method"] == "notifications/tasks/status"
            && notification["params"]["status"] == "completed"
            && notification["params"]["taskId"] == create_task["result"]["task"]["taskId"]
            && notification["params"].get("_meta").is_none()
    }));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_progresses_background_tasks_while_client_keeps_sending_requests() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "slow_echo",
                "arguments": {},
                "task": {}
            }
        }),
    );
    let (create_task, create_notifications) = read_response(&mut stdout, 2);
    assert!(create_notifications.is_empty());
    let task_id = create_task["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    let mut saw_completed_status = false;
    for ping_id in 3..=5 {
        send_message(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": ping_id,
                "method": "ping",
                "params": {}
            }),
        );
        let (ping_response, ping_notifications) = read_response(&mut stdout, ping_id);
        assert_eq!(ping_response["result"], json!({}));
        saw_completed_status |= ping_notifications.iter().any(|notification| {
            notification["method"] == "notifications/tasks/status"
                && notification["params"]["taskId"] == task_id
                && notification["params"]["status"] == "completed"
        });
    }

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tasks/get",
            "params": { "taskId": task_id }
        }),
    );
    let (task_get, task_get_notifications) = read_response(&mut stdout, 6);
    assert_eq!(task_get["result"]["status"], "completed");
    assert!(
        saw_completed_status
            || task_get_notifications.iter().any(|notification| {
                notification["method"] == "notifications/tasks/status"
                    && notification["params"]["taskId"] == create_task["result"]["task"]["taskId"]
                    && notification["params"]["status"] == "completed"
            })
    );

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_tags_nested_task_messages_with_related_task_metadata() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "sample this"},
                "task": {},
                "_meta": {"progressToken": "progress-task-sampled"}
            }
        }),
    );
    let (create_task, create_notifications) = read_response(&mut stdout, 2);
    assert!(create_notifications.is_empty());
    let task_id = create_task["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/result",
            "params": { "taskId": task_id }
        }),
    );
    let (task_result, notifications, nested_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 3);

    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "sampling/createMessage");
    assert_eq!(
        nested_requests[0]["params"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        create_task["result"]["task"]["taskId"]
    );

    let progress_notifications = notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/progress")
        .collect::<Vec<_>>();
    assert_eq!(progress_notifications.len(), 2);
    assert!(progress_notifications.iter().all(|notification| {
        notification["params"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"]
            == create_task["result"]["task"]["taskId"]
    }));

    let log_notifications = notifications
        .iter()
        .filter(|notification| notification["method"] == "notifications/message")
        .collect::<Vec<_>>();
    assert!(!log_notifications.is_empty());
    assert!(log_notifications.iter().all(|notification| {
        notification["params"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"]
            == create_task["result"]["task"]["taskId"]
    }));

    assert_eq!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        create_task["result"]["task"]["taskId"]
    );

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_parent_cancellation_during_tasks_result_marks_task_cancelled() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "cancel this task"},
                "task": {},
                "_meta": {"progressToken": "progress-task-cancelled"}
            }
        }),
    );
    let (create_task, create_notifications) = read_response(&mut stdout, 2);
    assert!(create_notifications.is_empty());
    let task_id = create_task["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (task_result, notifications, nested_requests) =
        read_response_with_nested_flow_cancellation(&mut stdout, &mut stdin, 3);

    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "sampling/createMessage");
    assert_eq!(task_result["result"]["isError"], true);
    assert_eq!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(task_result["result"]["content"][0]["text"]
        .as_str()
        .expect("cancelled task result text")
        .contains("cancelled by client: user aborted sample"));
    assert!(
        notifications.iter().any(|notification| {
            notification["method"] == "notifications/tasks/status"
                && notification["params"]["taskId"].as_str() == Some(task_id.as_str())
                && notification["params"]["status"].as_str() == Some("cancelled")
        }),
        "missing cancelled task status notification: {notifications:?}"
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (task_get, task_get_notifications) = read_response(&mut stdout, 4);
    assert!(task_get_notifications.is_empty());
    assert_eq!(task_get["result"]["status"], "cancelled");
    assert_eq!(
        task_get["result"]["ownership"]["terminalStateOwner"],
        "task"
    );

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_tasks_cancel_during_tasks_result_marks_task_cancelled() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo",
                "arguments": {"message": "cancel this task explicitly"},
                "task": {},
                "_meta": {"progressToken": "progress-task-explicit-cancel"}
            }
        }),
    );
    let (create_task, create_notifications) = read_response(&mut stdout, 2);
    assert!(create_notifications.is_empty());
    let task_id = create_task["result"]["task"]["taskId"]
        .as_str()
        .expect("task id")
        .to_string();

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (task_result, cancel_response, notifications, nested_requests) =
        read_response_with_explicit_task_cancellation(&mut stdout, &mut stdin, 3, 30, &task_id);

    assert_eq!(nested_requests.len(), 1);
    assert_eq!(nested_requests[0]["method"], "sampling/createMessage");
    assert_eq!(cancel_response["result"]["status"], "cancelled");
    assert_eq!(task_result["result"]["isError"], true);
    assert_eq!(
        task_result["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(task_result["result"]["content"][0]["text"]
        .as_str()
        .expect("cancelled task result text")
        .contains("task cancelled by client"));
    assert!(
        notifications.iter().any(|notification| {
            notification["method"] == "notifications/tasks/status"
                && notification["params"]["taskId"].as_str() == Some(task_id.as_str())
                && notification["params"]["status"].as_str() == Some("cancelled")
        }),
        "missing cancelled task status notification: {notifications:?}"
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }),
    );
    let (task_get, task_get_notifications) = read_response(&mut stdout, 4);
    assert!(task_get_notifications.is_empty());
    assert_eq!(task_get["result"]["status"], "cancelled");

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}

#[test]
fn mcp_serve_progresses_wrapped_sampling_tasks_while_upstream_keeps_talking() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo_tasked_noisy",
                "arguments": {"message": "sample this without waiting for idle"}
            }
        }),
    );
    let (sampled, sampled_notifications, sampled_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 2);
    assert_eq!(sampled_requests.len(), 1);
    assert_eq!(sampled_requests[0]["method"], "sampling/createMessage");
    assert_eq!(sampled["result"]["isError"], false);
    assert_eq!(
        sampled["result"]["structuredContent"]["taskStatusBeforeResult"],
        "completed"
    );
    assert_eq!(sampled["result"]["structuredContent"]["noiseCount"], 8);
    assert!(
        sampled["result"]["structuredContent"]["taskStatusNotifications"]
            .as_u64()
            .expect("task status notification count")
            >= 1
    );
    assert_eq!(
        sampled["result"]["structuredContent"]["sampled"]["content"]["text"],
        "sampled by client"
    );
    assert!(sampled_notifications
        .iter()
        .all(|notification| notification["method"] != "notifications/tasks/status"));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}
